#pragma once
#include <string>

namespace accord {
	// instance of the asset
	// only assets related to some detection must exist in the system

	class asset
	{
	public:
		std::string type;
		std::string value;

		asset();
		asset(std::string t, std::string v);
	};
}

