#pragma once

namespace accord {
	enum class security_state {
		non_compromised,
		potentially_compromised,
		compromised,
		remediated,
		whitelisted,
	};
}
