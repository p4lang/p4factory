/*
Copyright 2013-present Barefoot Networks, Inc. 

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Profiles control

// #define MULTICAST_DISABLE
// #define TUNNEL_DISABLE
// #define ACL_DISABLE

#ifdef MULTICAST_DISABLE
#define P4_MULTICAST_DISABLE
#endif

#ifdef TUNNEL_DISABLE
#define P4_TUNNEL_DISABLE
#endif

#ifdef ACL_DISABLE
#define P4_ACL_DISABLE
#endif
