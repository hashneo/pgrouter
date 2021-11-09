// NOLINT(namespace-envoy)
#include <string>
#include <unordered_map>

#include "proxy_wasm_intrinsics.h"

class AddSpiffeRootContext : public RootContext {
public:
  explicit AddSpiffeRootContext(uint32_t id, std::string_view root_id) : RootContext(id, root_id) {}
  bool onConfigure(size_t /* configuration_size */) override;

  bool onStart(size_t) override;
};

class AddSpiffeContext : public Context {
public:
  explicit AddSpiffeContext(uint32_t id, RootContext* root) : Context(id, root), root_(static_cast<AddSpiffeRootContext*>(static_cast<void*>(root))) {}

  void onCreate() override;

  FilterStatus onUpstreamData(size_t, bool) override;
  FilterStatus onDownstreamData(size_t, bool) override;

  void onDone() override;
  void onLog() override;
  void onDelete() override;
private:

  bool first_time_{true};

  AddSpiffeRootContext* root_;
};

static RegisterContextFactory register_AddSpiffeContext(CONTEXT_FACTORY(AddSpiffeContext),
                                                      ROOT_FACTORY(AddSpiffeRootContext),
                                                      "add_spiffe_root_id");

bool AddSpiffeRootContext::onConfigure(size_t config_buffer_length) {
  auto conf = getBufferBytes(WasmBufferType::PluginConfiguration, 0, config_buffer_length);
  LOG_WARN("onConfigure " + conf->toString());
  return true; 
}

bool AddSpiffeRootContext::onStart(size_t) { 
  LOG_WARN("onStart"); 
  return true;
}

void AddSpiffeContext::onCreate() { 
  LOG_WARN(std::string("onCreate " + std::to_string(id())));

  first_time_ = true;
}

// https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/advanced/attributes
constexpr std::string_view kConnection = "connection";
constexpr std::string_view kUriSanPeerCertificate = "uri_san_peer_certificate";

FilterStatus AddSpiffeContext::onUpstreamData(size_t size, bool) { 
    LOG_WARN(std::string("onUpstreamData called ")+ std::to_string(size));
    return FilterStatus::Continue; 
  }

FilterStatus AddSpiffeContext::onDownstreamData(size_t size, bool) { 

    LOG_WARN(std::string("onDownstreamData called ")+ std::to_string(size));

    if (first_time_) {

        LOG_WARN(std::string("onDownstreamData called for the first time "));
        first_time_ = false;
        // get the SAN from the connection
        std::string source_principal = "";
        getValue({kConnection, kUriSanPeerCertificate}, &source_principal);
        LOG_WARN(std::string("onDownstreamData source_principal is ")+source_principal);

        // prepend (start=0 & length=0) it to the buffer
        setBuffer(WasmBufferType::NetworkDownstreamData, 0, 0, source_principal+'\0');
    }

    return FilterStatus::Continue; 

}

void AddSpiffeContext::onDone() { 
  LOG_WARN(std::string("onDone " + std::to_string(id()))); 
}

void AddSpiffeContext::onLog() {
  LOG_WARN(std::string("onLog " + std::to_string(id()))); 
}

void AddSpiffeContext::onDelete() {
  LOG_WARN(std::string("onDelete " + std::to_string(id()))); 
}
