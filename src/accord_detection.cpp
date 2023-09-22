#include <string>
#include <chrono>
#include <iomanip>
#include <sstream>
#include "accord_detection.h"
#include "accord_tenant.h"
#include "SHA256.h"
#include "accord_security_state.h"

using namespace accord;

using time_point = std::chrono::system_clock::time_point;
std::string serialize_time_point(const time_point& time, const std::string& format)
{
	std::time_t tt = std::chrono::system_clock::to_time_t(time);
	std::tm tm;
	gmtime_s(&tm, &tt);
	std::stringstream ss;
	ss << std::put_time(&tm, format.c_str());
	return ss.str();
}

tenant& detection::get_owner()
{
	return owner;
}

bool accord::detection::is_active()
{
	switch (state)
	{
	case security_state::non_compromised:
	case security_state::remediated:
	case security_state::whitelisted:
		return false;
	}
	return true;
}

security_state detection::get_security_state()
{
	return state;
}

detection& detection::set_security_state(security_state new_state)
{
	state = new_state;
	return *this;
}


detection::detection(tenant& a_owner)
	: owner(a_owner)
{

}
detection& detection::add_property(std::string key, std::string value)
{
	this->properties[key] = value;
	return *this;
}
detection& detection::add_property(std::string key, std::chrono::system_clock::time_point timepoint)
{
	auto time_string = serialize_time_point(timepoint, "%Y-%m-%d %H:%M:%S");
	return add_property(key,time_string);
}
detection& detection::commit()
{
	// calc hash
	SHA256 sha256;
	for (auto const& [key, val] : properties)
	{
		sha256.update(key);
		sha256.update(val);
	}
	hash = SHA256::toString(sha256.digest());

	// notify other systems that detection has been commited
	owner.detection_created_observers.notify_all(*this);
	return *this;
}

std::string detection::get_hash()
{
	return std::string();
}
