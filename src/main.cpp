#include <iostream>
#include <chrono>
#include <list>

#include "accord_tenant.h"
#include "accord_core.h"
#include "accord_detection.h"
#include "accord_security_state.h"

void add_blocked_detections(accord::tenant& company, std::chrono::system_clock::time_point& timepoint)
{
	// blocked incoming detections can be considered remediated and will not contribute to security risks nor generate incidents
	company.create_detection()
		.add_property("Type", "AV Engine")
		.add_property("Occured", timepoint)
		.add_property("Name", "W32/Ransomware")
		.add_property("User", "John Doe")
		.add_property("Device", "DoePC")
		.add_property("filename", "ransomware.exe")
		.add_property("SHA1", "01aec95328395150e1c5c962f0c9296e2ae5040f")
		.add_property("RiskScore", std::to_string(100))
		.set_security_state(accord::security_state::remediated) // will not contribute to any incident nor create asset
		.commit();

	timepoint += std::chrono::seconds(10);

	for (int i = 0; i < 100; ++i)
	{
		company.create_detection()
			.add_property("Type", "URL blocker")
			.add_property("Occured", timepoint)
			.add_property("Name", "Blocked website")
			.add_property("User", "John Doe")
			.add_property("Device", "DoePC")
			.add_property("URL", std::string("http://blocked-website.com?") + std::to_string(i))
			.set_security_state(accord::security_state::remediated) // will not contribute to any incident nor create asset
			.add_property("RiskScore", std::to_string(10)) // this does not matter considering that it's auto-remediated
			.commit();

		timepoint += std::chrono::seconds(1);
	}

	// add one from Office365 email
	company.create_detection()
		.add_property("Type", "Office365 email")
		.add_property("Occured", timepoint)
		.add_property("Name", "E-mail attachmen blocked")
		.add_property("User", "John Doe")
		.add_property("E-mail", "john.doe@company1.com")
		.add_property("filename", "sth-blocked.scr")
		.add_property("SHA1", "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3")
		.commit();

	timepoint += std::chrono::minutes(1);
}

void add_detection_from_3rd_party(accord::tenant& company, std::chrono::system_clock::time_point& timepoint)
{
	company.create_detection()
		.add_property("Type", "3rd Party IPS")
		.add_property("Occured", timepoint)
		.add_property("Name", "Ransomware encryption key blocked")
		.add_property("Target IP", "188.120.100.5")
		.add_property("Device", "DoePC")
		.add_property("RiskScore", std::to_string(80))

		// would not contribute to incident 
		// .set_security_state(accord::security_state::remediated) 
		
		// however it's outgoing traffic and incident is not remediated
		.set_security_state(accord::security_state::compromised) 
		.commit();
	
	timepoint += std::chrono::seconds(1);

	company.create_detection()
		.add_property("Type", "3rd Party IDS")
		.add_property("Occured", timepoint)
		.add_property("Name", "Botnet communication detected")
		.add_property("Target IP", "188.120.100.5")
		.add_property("Device", "DoePC")
		.add_property("RiskScore", std::to_string(50))
		.set_security_state(accord::security_state::remediated) // will contribute to incident correlation
		.commit();

	timepoint += std::chrono::seconds(1);
}

void add_malware_process_on_a_PC(accord::tenant& company, std::chrono::system_clock:: time_point& timepoint)
{
	company.create_detection()
		.add_property("Type", "EEI Rule")
		.add_property("Occured", timepoint)
		.add_property("Name", "Program with poor reputation added to auto-start")
		.add_property("User", "John Doe")
		.add_property("Device", "DoePC")
		.add_property("Process", "ProcessUniqueID_1")
		.add_property("filename", "file1.exe")
		.add_property("SHA1", "2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12")
		.add_property("RiskScore", std::to_string(20))
		.commit();

	timepoint += std::chrono::milliseconds(10);

	// repeated alarms should be processed only once (by their uniqueness)
	for (int i = 0; i < 100; ++i)
	{
		company.create_detection()
			.add_property("Type", "EEI Rule")
			.add_property("Occured", timepoint)
			.add_property("Name", "Exe file creation or modification")
			.add_property("User", "John Doe")
			.add_property("Device", "DoePC")
			.add_property("Process", "ProcessUniqueID_1")
			.add_property("filename", "file1.exe")
			.add_property("SHA1", "2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12")
			.add_property("RiskScore", std::to_string(30))
			.commit();

		timepoint += std::chrono::milliseconds(10);
	}

	company.create_detection()
		.add_property("Type", "EEI Rule")
		.add_property("Occured", timepoint)
		.add_property("Name", "Filecoder behavior")
		.add_property("User", "John Doe")
		.add_property("Device", "DoePC")
		.add_property("Process", "ProcessUniqueID_1")
		.add_property("filename", "file1.exe")
		.add_property("SHA1", "2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12")
		.add_property("RiskScore", std::to_string(40))
		.commit();

	timepoint += std::chrono::milliseconds(10);

	// here we reached the risk score 90 for the process, so still less than required 100

	auto detection = company.create_detection()
		.add_property("Type", "EEI Rule")
		.add_property("Occured", timepoint)
		.add_property("Name", "Filecoder behavior")
		.add_property("User", "John Doe")
		.add_property("Device", "DoePC")
		.add_property("Process", "ProcessUniqueID_1")
		.add_property("filename", "file1.exe")
		.add_property("SHA1", "2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12")
		.add_property("RiskScore", std::to_string(40))
		.commit();

	timepoint += std::chrono::milliseconds(10);

}


void create_detections(accord::tenant& company)
{
	auto timepoint = std::chrono::system_clock().now();

	add_blocked_detections(company, timepoint);
	add_malware_process_on_a_PC(company, timepoint);
	add_detection_from_3rd_party(company, timepoint);

}

int main(void)
{
	accord::core accord;

	std::list <accord::tenant> tenants_db;
	auto company = tenants_db.emplace_back("company1");

	// set assets that we are going to monitor for compromise

	accord.monitor_asset_type("User");
	accord.monitor_asset_type("Device");
	accord.monitor_asset_type("Process");

	accord.monitor_tenant(company);

	create_detections(company);

	//	tenant.configure().set_detection_cooldown();
	return 0;
}
