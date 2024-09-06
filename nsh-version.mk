# This Makefile controls the nsh version number.
#
# It adds a version number suffix ("-current") to binaries compiled
# from the nsh.git repository, while nsh releases built from an
# nsh-1.x.tar.gz release artifact announce their version number
# without a suffix.
#
# Before creating a release, review commits made since the previous
# release (1.y) and write a change log for end users to be published
# on the web site.
# Review commits with Git: git log --reverse v1.y..master
# Review commits With Got: got log -R -x v1.y -c master | less
# 
# The release workflow is:
# 
# 1) Obtain a clean Git or Got work tree of the nsh master branch.
# 
# 2) Bump the NSH_VERSION_NUMBER variable in this file.
#
# 3) Run 'make release' to create nsh-1.x.tar.gz.
#
#    This command may throw minor errors which relate to 
#    changes to nsh-dist.txt if that is the case then a file called
#    nsh-dist.txt.new will be created. Review the changes and decide
#    what to do about each newly added or removed file.
#
#    If all changes are expected changes to the packaging list, then
#    a simple rename and commit will do:
#      mv nsh-dist.txt.new nsh-dist.txt
#      git/got commit -m 'sync dist file list' nsh-dist.txt
#
#    Unwanted added files picked up by 'make release' may require some work.
#    Such files will usually fall into 2 categories:
#      a) Unversioned files in the work tree created during the nsh build.
#         These must be added to CLEANFILES, usually in the top-level
#         Makefile, such that 'make clean' will remove them. Make sure
#         to commit any related Makefile fixes and send them to the main
#         nsh.git repository.
#      b) Other unversioned files left behind in the work tree must be
#         removed manually before 'make release' is run again.
#         For example, .o or .d files may be left behind in obj/ directories
#         in case the corresponding source files are on longer listed in the
#         $SRCS Makefile variable. Just remove them.
#
#    Before running 'make release' again, ensure your work tree is clean.
#    In any case, remove botched generated tarballs and new dist-list files:
#      rm nsh-1.x.tar.gz nsh-dist.txt.new
#    If an error left behind any nsh-version.mk modifications, revert them,
#    keeping the version number bump intact:
#      With Git: git restore -p nsh-version.mk
#      With Got: got revert -p nsh-version.mk
#  
# 4) Copy nsh-1.x.tar.gz to /usr/ports/distfiles and update the
#    nsh port in /usr/ports/shells/nsh to the new release.
#
#    At a minimum, upgrade steps for the port involve:
#     a) cp nsh-1.x.tar.gz /usr/ports/distfiles
#     b) adjust the version number in /usr/ports/shells/nsh/Makefile
#     c) cd /usr/ports/shells/nsh; make makesum; make package
#
#    At this point, no release tag has been published so it is easy to
#    fix things in case a problem is found while updating the port.
#    Keep regenerating nsh-1.x.tar.gz as above until the port is happy.
#    Commit your fixes to the nsh master branch, taking care not to
#    commit the version bump yet. Send your fixes to the main repository.
#    Don't forget to ask for review of non-trivial fixes.
#
# 5) Bump the NSH_VERSION variable in this file, and, this time, commit.
#
# 6) Create a release tag and send it to the main nsh.git repository:
#
#    With Git: git tag v1.x master; git push origin v1.x
#    With Got: got tag -c master v1.x; got send -t v1.x
#    Or use the Github web UI.
#
#    Now the release is official. If a blocking issue is found after
#    this point, then the release version number has been burned.
#    *DO NOT* re-use the same version number to issue a fixed release.
#    Restart the entire release process with a new number instead of
#    creating confusion about whether a given release is good or bad.
#    Numbers are infinite, but people's attention span isn't.
#    A bad release can be marked as "Not released" in the change log,
#    and the uploaded release asset can be deleted again.
#
# 7) Create a "Release" in the Github web UI based on the new v1.x tag,
#    and make sure to upload /usr/ports/distfiles/nsh-1.x.tar.gz as an asset
#    via the release form. The ports tree will fetch it from there.

# NSH_RELEASE is set to "Yes" in a release tarball by 'make release'
# There is no need to fiddle with this manually.
NSH_RELEASE=No

# Version number of the most recently published release.
# Should be cranked immediately before publishing a new release.
NSH_VERSION_NUMBER=1.2.2

.if ${NSH_RELEASE} == Yes
NSH_VERSION=${NSH_VERSION_NUMBER}
.else
NSH_VERSION=${NSH_VERSION_NUMBER}-current
.endif
