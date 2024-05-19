rm -rf build

mkdir build
cd build

cmake ../ -DCMAKE_BUILD_TYPE=Debug -DENABLE_GCOV=1
make -j8

./JwtUtilTest

cd ..

set COVERAGE_FILE coverage.info
set REPORT_FOLDER coverage_report
lcov --rc lcov_branch_coverage=1 -c -d build -o {$COVERAGE_FILE}_tmp
lcov --rc lcov_branch_coverage=1 -e {$COVERAGE_FILE}_tmp "*src*" -o {$COVERAGE_FILE}
genhtml --rc genhtml_branch_coverage=1 {$COVERAGE_FILE} -o {$REPORT_FOLDER}
rm -rf {$COVERAGE_FILE}_tmp
rm -rf {$COVERAGE_FILE}
