#include <cstdint>
#include <cstdlib>
#include <memory>
#include <mutex>

#include <grpcpp/grpcpp.h>

#include "remote_secu.grpc.pb.h"
#include "secu_defs.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

class SecuClient {
public:
  explicit SecuClient(std::shared_ptr<Channel> channel)
    : stub_(secu::SecuService::NewStub(channel)) {}

  uint64_t IntegrityInit(int algorithm, const uint8_t *key) {
    secu::StreamInitRequest req;
    req.set_algorithm(algorithm);
    req.set_key(key, 16); 

    secu::StreamInitResponse rsp;
    ClientContext ctx;
    Status st = stub_->StreamIntegrityInit(&ctx, req, &rsp);
    if (!st.ok()) {
      return 0;
    }
    return rsp.ctx_id();
  }

  void IntegrityFree(uint64_t ctx_id) {
    secu::StreamFreeRequest req;
    req.set_ctx_id(ctx_id);
    google::protobuf::Empty rsp;
    ClientContext ctx;
    (void)stub_->StreamIntegrityFree(&ctx, req, &rsp);
  }

  uint64_t CipheringInit(int algorithm, const uint8_t *key) {
    secu::StreamInitRequest req;
    req.set_algorithm(algorithm);
    req.set_key(key, 16);

    secu::StreamInitResponse rsp;
    ClientContext ctx;
    Status st = stub_->StreamCipheringInit(&ctx, req, &rsp);
    if (!st.ok()) {
      return 0;
    }
    return rsp.ctx_id();
  }

  void CipheringFree(uint64_t ctx_id) {
    secu::StreamFreeRequest req;
    req.set_ctx_id(ctx_id);
    google::protobuf::Empty rsp;
    ClientContext ctx;
    (void)stub_->StreamCipheringFree(&ctx, req, &rsp);
  }

  void ComputeIntegrity(eia_alg_id_e alg,
                        const nas_stream_cipher_t *sc,
                        uint8_t out[4]) {
    secu::IntegrityRequest req;
    req.set_alg(static_cast<secu::EiaAlg>(alg));

    secu::NasStreamCipher *nsc = req.mutable_sc();
    uint64_t ctx_id = (uint64_t)(uintptr_t)sc->context->context;
    nsc->set_ctx_id(ctx_id);
    nsc->set_count(sc->count);
    nsc->set_bearer(sc->bearer);
    nsc->set_direction(sc->direction);
    nsc->set_message(sc->message, (sc->blength + 7) / 8);
    nsc->set_blength(sc->blength);

    secu::IntegrityResponse rsp;
    ClientContext ctx;
    Status st = stub_->StreamComputeIntegrity(&ctx, req, &rsp);
    if (!st.ok() || rsp.mac().size() < 4) {
      for (int i = 0; i < 4; ++i) out[i] = 0;
      return;
    }
    memcpy(out, rsp.mac().data(), 4);
  }

  void ComputeEncrypt(eea_alg_id_e alg,
                      const nas_stream_cipher_t *sc,
                      uint8_t *out) {
    secu::EncryptRequest req;
    req.set_alg(static_cast<secu::EeaAlg>(alg));

    secu::NasStreamCipher *nsc = req.mutable_sc();
    uint64_t ctx_id = (uint64_t)(uintptr_t)sc->context->context;
    nsc->set_ctx_id(ctx_id);
    nsc->set_count(sc->count);
    nsc->set_bearer(sc->bearer);
    nsc->set_direction(sc->direction);
    size_t bytes = (sc->blength + 7) / 8;
    nsc->set_message(sc->message, bytes);
    nsc->set_blength(sc->blength);

    secu::EncryptResponse rsp;
    ClientContext ctx;
    Status st = stub_->StreamComputeEncrypt(&ctx, req, &rsp);
    if (!st.ok() || rsp.data().size() < bytes) {
      // si falla, copia el mensaje original
      memcpy(out, sc->message, bytes);
      return;
    }
    memcpy(out, rsp.data().data(), bytes);
  }

private:
  std::unique_ptr<secu::SecuService::Stub> stub_;
};

static std::unique_ptr<SecuClient> g_client;
static std::once_flag g_client_once;

static void init_client_once()
{
  // IP:PUERTO de tu servidor
  std::string target = "192.168.112.24:50051";
  auto channel = grpc::CreateChannel(target, grpc::InsecureChannelCredentials());
  g_client.reset(new SecuClient(channel));
}

static SecuClient* get_client()
{
  std::call_once(g_client_once, init_client_once);
  return g_client.get();
}

extern "C" {

stream_security_context_t *stream_integrity_init(int integrity_algorithm,
                                                 const uint8_t *integrity_key)
{
  SecuClient *c = get_client();
  uint64_t id = c->IntegrityInit(integrity_algorithm, integrity_key);

  if (id == 0) return nullptr;

  stream_security_context_t *ctx =
      (stream_security_context_t*)calloc(1, sizeof(*ctx));
  ctx->context = (void*)(uintptr_t)id;
  return ctx;
}

void stream_integrity_free(int integrity_algorithm,
                           stream_security_context_t *integrity_context)
{
  (void)integrity_algorithm; // ya está implícito en el contexto remoto
  if (!integrity_context) return;
  SecuClient *c = get_client();
  uint64_t id = (uint64_t)(uintptr_t)integrity_context->context;
  c->IntegrityFree(id);
  free(integrity_context);
}

stream_security_context_t *stream_ciphering_init(int ciphering_algorithm,
                                                 const uint8_t *ciphering_key)
{
  SecuClient *c = get_client();
  uint64_t id = c->CipheringInit(ciphering_algorithm, ciphering_key);

  if (id == 0) return nullptr;

  stream_security_context_t *ctx =
      (stream_security_context_t*)calloc(1, sizeof(*ctx));
  ctx->context = (void*)(uintptr_t)id;
  return ctx;
}

void stream_ciphering_free(int ciphering_algorithm,
                           stream_security_context_t *ciphering_context)
{
  (void)ciphering_algorithm;
  if (!ciphering_context) return;
  SecuClient *c = get_client();
  uint64_t id = (uint64_t)(uintptr_t)ciphering_context->context;
  c->CipheringFree(id);
  free(ciphering_context);
}

void stream_compute_integrity(eia_alg_id_e alg,
                              nas_stream_cipher_t const* stream_cipher,
                              uint8_t out[4])
{
  SecuClient *c = get_client();
  c->ComputeIntegrity(alg, stream_cipher, out);
}

void stream_compute_encrypt(eea_alg_id_e alg,
                            nas_stream_cipher_t const* stream_cipher,
                            uint8_t *out)
{
  SecuClient *c = get_client();
  c->ComputeEncrypt(alg, stream_cipher, out);
}

stream_security_container_t *stream_security_container_init(int ciphering_algorithm,
                                                            int integrity_algorithm,
                                                            const uint8_t *ciphering_key,
                                                            const uint8_t *integrity_key)
{
  stream_security_container_t *container = (stream_security_container_t*)calloc(1, sizeof(*container));
  if (!container) return nullptr;

  container->integrity_algorithm = integrity_algorithm;
  container->ciphering_algorithm = ciphering_algorithm;

  /* Delegar la inicialización al servidor remoto */
  container->integrity_context = stream_integrity_init(integrity_algorithm, integrity_key);
  container->ciphering_context = stream_ciphering_init(ciphering_algorithm, ciphering_key);

  return container;
}

void stream_security_container_delete(stream_security_container_t *container)
{
  /* passing NULL is accepted */
  if (container == NULL)
    return;

  /* Delegar la liberación al servidor remoto */
  stream_integrity_free(container->integrity_algorithm, container->integrity_context);
  stream_ciphering_free(container->ciphering_algorithm, container->ciphering_context);
  free(container);
}

} // extern "C"
