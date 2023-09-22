#include "accord_core.h"
#include "accord_asset.h"
#include "accord_detection.h"

class detection;
using namespace accord;

void core::monitor_asset_type(std::string type)
{
	monitored_asset_types.insert(type);
}

void core::monitor_tenant(tenant& to_monitor)
{
	auto delegate = std::bind(&core::process_new_detection, this, std::placeholders::_1);
	to_monitor.detection_created_observers.add_listener( delegate );
}


void check_if_incident_happened(asset& to_process)
{

}

void core::process_new_detection(detection& new_detection)
{
	std::cout << "Processing detection" << std::endl;

	if (!new_detection.is_active())
	{
		std::cout << "Detection is auto-remediated, nothing to do with it" << std::endl;
		return;
	}

	auto detection_tenant = new_detection.get_owner();
	// add assets for monitoring
	for (auto const& [key, val] : new_detection.properties)
	{
		if (monitored_asset_types.find(key) != monitored_asset_types.end())
		{
			auto has_asset = detection_tenant.get_asset(key, val);
			if (!has_asset.has_value())
				detection_tenant.create_asset(key, val);
		}
	}

	// add this detectioon to each asset
	for (auto const& asset_in_detection : get_monitored_assets_for_detection(new_detection))
	{
//		if (asset_in_detection.get().get_risk_score() >= 100)
//			process_detection_as_incident(new_detection);
	}


	// check risk score for each asset
	for (auto const& asset_in_detection : get_monitored_assets_for_detection(new_detection))
	{
//		if (asset_in_detection.get().get_risk_score() >= 100)
//			process_detection_as_incident(new_detection);
	}
}

std::list <std::reference_wrapper<asset>> core::get_monitored_assets_for_detection(detection& to_process)
{
	std::list <std::reference_wrapper<asset>> monitored_assets;
	return monitored_assets;
}
