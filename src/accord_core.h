#pragma once
#include <string>
#include <set>

#include "accord_tenant.h"

// Automatic CORrelation of Detections

/*
* For simplification of PoC we do not use any Relational Database here nor IDs to interconnect entities
* To show relations we use in-memory data structures and references
*/

namespace accord {
	class tenant;
	class detection;

	class core {
		std::set <std::string> monitored_asset_types;
		std::list <tenant> tenants;

		void is_asset_monitored(tenant& t, std::string type, std::string value);
		void start_monitoring_asset(tenant& t, std::string type, std::string value);
		std::list <std::reference_wrapper<asset>> get_monitored_assets_for_detection(detection& to_process);

	public:

		void monitor_asset_type(std::string type);
		void process_new_detection(detection& to_process);
		void monitor_tenant(tenant& to_monitor);
	};
}
