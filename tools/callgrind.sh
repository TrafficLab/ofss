valgrind                               \
  --time-stamp=yes                     \
  --tool=callgrind                     \
  --callgrind-out-file=callgrind.out   \
  --sim-hints=lax-ioctls               \
  ./ofss $*


# callgrind_annotate callgrind.out
# callgrind_annotate –inclusive=yes callgrind.out
