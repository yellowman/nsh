# NSH_RELEASE is only set to "Yes" in a release tarball
NSH_RELEASE=No

# Version number of the most recently published release.
# Should be cranked immediately before publishing a new release.
NSH_VERSION_NUMBER=1.2

.if ${NSH_RELEASE} == Yes
NSH_VERSION=${NSH_VERSION_NUMBER}
.else
NSH_VERSION=${NSH_VERSION_NUMBER}-current
.endif
