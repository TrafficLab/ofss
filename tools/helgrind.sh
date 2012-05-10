valgrind                               \
  --tool=helgrind                      \
  --num-callers=50                     \
  --show-below-main=yes                \
  --read-var-info=yes                  \
  --sim-hints=lax-ioctls               \
  --suppressions=tools/valgrind.supp   \
  ./ofss $*


#  --track-fds=yes                      \
#  --show-emwarns=yes                   \
