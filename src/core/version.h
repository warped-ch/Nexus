/*******************************************************************************************

            Hash(BEGIN(Satoshi[2010]), END(Sunny[2012])) == Videlicet[2014] ++

 [Learn and Create] Viz. http://www.opensource.org/licenses/mit-license.php

*******************************************************************************************/

#ifndef NEXUS_VERSION_H
#define NEXUS_VERSION_H

#include <string>

#define DATABASE_MAJOR       0
#define DATABASE_MINOR       1
#define DATABASE_REVISION    1
#define DATABASE_BUILD       0

#define PROTOCOL_MAJOR       0
#define PROTOCOL_MINOR       1
#define PROTOCOL_REVISION    1
#define PROTOCOL_BUILD       0

/** Used to determine the current features available on the local database */
extern const int DATABASE_VERSION;

/** Used to determine the features available in the Nexus Network **/
extern const int PROTOCOL_VERSION;

/** Used to Lock-Out Nodes that are running a protocol version that is too old,
    Or to allow certain new protocol changes without confusing Old Nodes. **/
extern const int MIN_PROTO_VERSION;

/** These external variables are the display only variables. They are used to track the updates of Nexus independent of Database and Protocol Upgrades. **/
extern const std::string CLIENT_NAME;
extern const std::string CLIENT_BUILD;
extern const std::string CLIENT_DATE;


#endif
