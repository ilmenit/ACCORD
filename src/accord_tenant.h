#pragma once
#include <map>
#include <string>
#include <set>
#include <optional>

#include "accord_asset.h"
#include "accord_incident.h"
#include "accord_detection.h"
#include "accord_event.h"

namespace accord {
	
	class asset;
	class incident;
	class detection;

	// tenant is equivalent of isolated relational database storage
	// https://docs.microsoft.com/en-us/azure/azure-sql/database/saas-tenancy-app-design-patterns
	// In PoC instead of tables and IDs we just use list and references

	class tenant
	{
	public:

		std::string name;

		// lists are used for code simplificaiton in PoC
		std::list<incident> incidents;
		std::list<detection> detections;
		std::list<asset> assets;

		event<detection> detection_created_observers;

		tenant();
		tenant(std::string a_name);

		// creating entities
		detection& create_detection();		
		incident& create_incident();
		asset& create_asset(std::string type, std::string value);

		// getting entities
		std::optional<std::reference_wrapper<asset>> get_asset(std::string type, std::string value);
	};


}

