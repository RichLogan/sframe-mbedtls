#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <sframe/test_suite.h>
#include "mbedtls.h"

using namespace sframe::provider::mbedtls;
TYPE_TO_STRING_AS("MbedTLS", MbedTLSProvider);
TEST_CASE_TEMPLATE_INVOKE(test_suite, MbedTLSProvider);