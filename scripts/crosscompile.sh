#!/usr/bin/env bash
set -u

version="2.0-001"
git_root_path=`git rev-parse --show-toplevel`

go mod download

echo "Performing tests on all modules..."
go test ./...
if [ $? != "0" ] 
then
  echo "Tests on all modules failed."
  echo "Press any key to continue compilation or CTRL+C to abort."
  read
else 
  echo "Tests on all modules passed."
fi

cd ${git_root_path}/scripts;

mkdir -p ${git_root_path}/binaries/${version};

rm -f ${git_root_path}/binaries/latest; 

cd ${git_root_path}/binaries; ln -s ${version} latest; cd ${git_root_path}/scripts;

for os in android aix darwin dragonfly freebsd illumos ios js linux netbsd openbsd plan9 solaris windows zos;
#for os in windows;
do
  for arch in "amd64" "386" "arm" "arm64" "mips64" "mips64le" "mips" "mipsle" "ppc64" "ppc64le" "riscv64" "s390x" "wasm" 
  do
    execution_file="sitebrush"
    build_flags=""
    target_os_name=${os}
    [ "$os" == "windows" ] && execution_file="sitebrush.exe" && build_flags="-H windowsgui "
    [ "$os" == "darwin" ] && target_os_name="mac"

    #compile gui app:
    GOOS=${os} GOARCH=${arch} go build -tags gui -ldflags "${build_flags}-X sitebrush/pkg/config.CompileVersion=${version}" -o ${execution_file} .. 2> /dev/null

    if [ "$?" == "0" ]
    then
      mkdir -p ../binaries/${version}/gui/${target_os_name}/${arch}
      chmod +x ${execution_file}
      mv ${execution_file} ../binaries/${version}/gui/${target_os_name}/${arch}/
      echo "GOOS=${os} GOARCH=${arch} go build -tags gui -ldflags '${build_flags}-X sitebrush/pkg/config.CompileVersion=${version}' -o ../binaries/${version}/gui/${target_os_name}/${arch}/${execution_file} .."
    fi

    #compile non gui app:
    GOOS=${os} GOARCH=${arch} go build -ldflags "-X sitebrush/pkg/config.CompileVersion=${version}" -o ${execution_file} .. 2> /dev/null

    if [ "$?" == "0" ]
    then
      mkdir -p ../binaries/${version}/no-gui/${target_os_name}/${arch}
      chmod +x ${execution_file}
      mv ${execution_file} ../binaries/${version}/no-gui/${target_os_name}/${arch}/
      echo "GOOS=${os} GOARCH=${arch} go build -ldflags '-X sitebrush/pkg/config.CompileVersion=${version}' -o ../binaries/${version}/no-gui/${target_os_name}/${arch}/${execution_file} .."
    fi

  done
done

#optional: publish to internet:
if [ "${PUBLISH:-0}" == "1" ]
then
  rsync -avP ../binaries/* files@files.matveynator.ru:/home/files/public_html/sitebrush/
else
  echo "Skipping publish. Set PUBLISH=1 to rsync binaries to the public server."
fi
