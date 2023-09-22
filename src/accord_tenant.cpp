#include "accord_tenant.h"

using namespace accord;

accord::tenant::tenant()
{
}

accord::tenant::tenant(std::string a_name)
	: name(a_name)
{
}

detection& tenant::create_detection()
{
	detection& created = detections.emplace_back(*this);
	return created;
}

asset& tenant::create_asset(std::string type, std::string value)
{
	// check if we already have this as a monitored asset
	return assets.emplace_back(asset(type, value));
}

std::optional<std::reference_wrapper<asset>> tenant::get_asset(std::string type, std::string value)
{
	for (auto& monitored : assets)
	{
		if (monitored.type == type && monitored.value == value)
			return monitored;
	}
	return {};
}
