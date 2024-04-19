set(VERSION 2.0.0)
#
# Modify REF to latest commit id from https://github.com/apache/apr
# Update SHA512 with actual SHA512
#
vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO apache/apr
    REF 6445e8804008922f8018aa238aa4d6bba608c49a
    SHA512 0
    HEAD_REF trunk
)

if (VCPKG_TARGET_IS_WINDOWS)
    vcpkg_check_features(OUT_FEATURE_OPTIONS FEATURE_OPTIONS
        FEATURES
            private-headers INSTALL_PRIVATE_H
            crypto FEATURE_CRYPTO
            xlate FEATURE_XLATE
            dbd-sqlite3 FEATURE_DBD_SQLITE3
    )

    string(COMPARE EQUAL "${VCPKG_LIBRARY_LINKAGE}" "static" APR_BUILD_STATIC)
    string(COMPARE EQUAL "${VCPKG_LIBRARY_LINKAGE}" "dynamic" APR_BUILD_SHARED)

    vcpkg_cmake_configure(
        SOURCE_PATH "${SOURCE_PATH}"
        OPTIONS
            -DAPR_BUILD_STATIC=${APR_BUILD_STATIC}
            -DAPR_BUILD_SHARED=${APR_BUILD_SHARED}
            -DINSTALL_PDB=OFF
            -DAPU_HAVE_CRYPTO=${FEATURE_CRYPTO}
            -DAPU_HAVE_ICONV=${FEATURE_XLATE}
            -DAPU_HAVE_SQLITE3=${FEATURE_DBD_SQLITE3}
            -DAPU_USE_EXPAT=ON
            -DAPR_INSTALL_PRIVATE_H=${INSTALL_PRIVATE_H}
    )

    vcpkg_cmake_install()
    vcpkg_copy_pdbs()
else()
    # In development
endif()

# Handle copyright
file(INSTALL "${SOURCE_PATH}/LICENSE" DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}" RENAME copyright)

