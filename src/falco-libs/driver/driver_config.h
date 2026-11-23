// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*

Copyright (C) 2023 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/
#pragma once

/* taken from driver/API_VERSION */
#define PPM_API_CURRENT_VERSION_MAJOR 11
#define PPM_API_CURRENT_VERSION_MINOR 0
#define PPM_API_CURRENT_VERSION_PATCH 1

/* taken from driver/SCHEMA_VERSION */
#define PPM_SCHEMA_CURRENT_VERSION_MAJOR 4
#define PPM_SCHEMA_CURRENT_VERSION_MINOR 5
#define PPM_SCHEMA_CURRENT_VERSION_PATCH 3

#include <driver/ppm_api_version.h>

#define DRIVER_VERSION "0.0.0"

#define DRIVER_NAME "scap"

#define DRIVER_DEVICE_NAME "scap"

#define DRIVER_COMMIT "0"

#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME DRIVER_NAME
#endif
