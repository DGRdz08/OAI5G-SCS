#include <atomic>
#include <cstdint>
#include <unordered_map>
#include <mutex>

#include <grpcpp/grpcpp.h>

#include "remote_secu.grpc.pb.h"
extern "C" {
#include "secu_defs.h"  
}

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

struct ContextEntry {
  int algorithm;
  stream_security_context_t *ctx;
};

class SecuServiceImpl final : public secu::SecuService::Service {
public:
  SecuServiceImpl() : next_id_(1) {}

  Status StreamIntegrityInit(ServerContext*,const secu::StreamInitRequest* req,secu::StreamInitResponse* rsp) override {
    int alg = req->algorithm(); // Obtener el algoritmo del request 
    const std::string &key = req->key();

    stream_security_context_t *ctx =
        stream_integrity_init(alg, (const uint8_t*)key.data());

    uint64_t id = alloc_id();
    {
      std::lock_guard<std::mutex> lock(m_);
      integrity_ctx_[id] = {alg, ctx};
    }
    rsp->set_ctx_id(id);
    return Status::OK;
  }

  Status StreamIntegrityFree(ServerContext*,
                             const secu::StreamFreeRequest* req,
                             google::protobuf::Empty*) override {
    uint64_t id = req->ctx_id();
    ContextEntry entry;
    {
      std::lock_guard<std::mutex> lock(m_);
      auto it = integrity_ctx_.find(id); // Se busca el contexto 
      if (it == integrity_ctx_.end()) {
        return Status::OK;
      }
      entry = it->second;
      integrity_ctx_.erase(it);
    }
    stream_integrity_free(entry.algorithm, entry.ctx);
    return Status::OK;
  }

  Status StreamCipheringInit(ServerContext*, const secu::StreamInitRequest* req, secu::StreamInitResponse* rsp) override {
    int alg = req->algorithm();
    const std::string &key = req->key();

    stream_security_context_t *ctx = stream_ciphering_init(alg, (const uint8_t*)key.data());

    uint64_t id = alloc_id();
    {
      std::lock_guard<std::mutex> lock(m_);
      cipher_ctx_[id] = {alg, ctx};
    }
    rsp->set_ctx_id(id);
    return Status::OK;
  }

  Status StreamCipheringFree(ServerContext*, const secu::StreamFreeRequest* req, google::protobuf::Empty*) override {
    uint64_t id = req->ctx_id();
    ContextEntry entry;
    {
      std::lock_guard<std::mutex> lock(m_);
      auto it = cipher_ctx_.find(id);
      if (it == cipher_ctx_.end()) {
        return Status::OK;
      }
      entry = it->second;
      cipher_ctx_.erase(it);
    }
    stream_ciphering_free(entry.algorithm, entry.ctx);
    return Status::OK;
  }

  Status StreamComputeIntegrity(ServerContext*,const secu::IntegrityRequest* req, secu::IntegrityResponse* rsp) override {
    eia_alg_id_e alg = (eia_alg_id_e)req->alg();
    const secu::NasStreamCipher &nsc = req->sc();

    ContextEntry entry;
    {
      std::lock_guard<std::mutex> lock(m_);
      auto it = integrity_ctx_.find(nsc.ctx_id());
      if (it == integrity_ctx_.end()) {
        return grpc::Status(grpc::StatusCode::NOT_FOUND, "Unknown integrity ctx_id");
      }
      entry = it->second;
    }

    nas_stream_cipher_t sc;
    sc.context   = entry.ctx;
    sc.count     = nsc.count();
    sc.bearer    = (uint8_t)nsc.bearer();
    sc.direction = (uint8_t)nsc.direction();
    sc.blength   = nsc.blength();
    // el puntero apunta a datos dentro del mensaje protobuf mientras dure la llamada
    sc.message   = (uint8_t*)const_cast<char*>(nsc.message().data());

    uint8_t mac[4] = {0};
    stream_compute_integrity(alg, &sc, mac);

    rsp->set_mac(mac, 4); //set_mac espera un puntero y tamaño y los copia
    return Status::OK;
  }

  Status StreamComputeEncrypt(ServerContext*, const secu::EncryptRequest* req, secu::EncryptResponse* rsp) override {
    eea_alg_id_e alg = (eea_alg_id_e)req->alg();
    const secu::NasStreamCipher &nsc = req->sc();

    ContextEntry entry;
    {
      std::lock_guard<std::mutex> lock(m_);
      auto it = cipher_ctx_.find(nsc.ctx_id());
      if (it == cipher_ctx_.end()) {
        return grpc::Status(grpc::StatusCode::NOT_FOUND, "Unknown cipher ctx_id");
      }
      entry = it->second;
    }

    nas_stream_cipher_t sc;
    sc.context   = entry.ctx;
    sc.count     = nsc.count();
    sc.bearer    = (uint8_t)nsc.bearer();
    sc.direction = (uint8_t)nsc.direction();
    sc.blength   = nsc.blength();
    sc.message   = (uint8_t*)const_cast<char*>(nsc.message().data());

    size_t bytes = (sc.blength + 7) / 8;
    std::string out;
    out.resize(bytes);
    stream_compute_encrypt(alg, &sc, (uint8_t*)&out[0]);

    rsp->set_data(out);
    return Status::OK;
  }

private:
  uint64_t alloc_id() { return next_id_++; }

  std::mutex m_;
  std::unordered_map<uint64_t, ContextEntry> integrity_ctx_;
  std::unordered_map<uint64_t, ContextEntry> cipher_ctx_;
  std::atomic<uint64_t> next_id_;
};

static void RunServer()
{
  std::string address("0.0.0.0:50051"); 

  SecuServiceImpl service;
  ServerBuilder builder;
  builder.AddListeningPort(address, grpc::InsecureServerCredentials());
  builder.RegisterService(&service);
  std::unique_ptr<Server> server(builder.BuildAndStart());
  std::cout << "Servicio escuchando en " << address << std::endl;
  server->Wait(); 
}

int main(int argc, char **argv)
{
  (void)argc; (void)argv;
  RunServer();
  return 0;
}
