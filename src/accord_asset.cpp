#include "accord_asset.h"

using namespace accord;

asset::asset()
{
}

asset::asset(std::string t, std::string v)
:type(t), value(v)
{
}
