#pragma once
#include <string>
#include <list>
#include <map>
#include <chrono>

#include "accord_security_state.h"

namespace accord {

	class tenant;
//	enum security_state;
	/*
	* detection is an alarm generated from some detection system like EEI Rules or AV Detections
	* their context is made of detection properties
	*/
	class detection
	{
		/*
		* detection properties form context of detections
		*
		* detection_property is for instance:
		* User = "John Doe" or Severity Score = 85
		*
		* For the code simplification in the PoC only the std::strings are used here
		*/
		std::string hash;
		tenant& owner;
		security_state state = security_state::compromised;

	public:
		std::map<std::string, std::string> properties;

		detection(tenant& a_owner);
		tenant& get_owner();
		detection& add_property(std::string key, std::string value);
		detection& add_property(std::string key, std::chrono::system_clock::time_point timepoint);
		// finish adding properties and calculate hash
		detection& commit();
		std::string get_hash(); // for detection uniqueness

		bool is_active(); 
		security_state get_security_state();
		detection& set_security_state(security_state new_state);

	};
}
