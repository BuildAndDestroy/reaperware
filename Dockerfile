FROM golang:1.23.1-bullseye
RUN apt update -y
RUN apt upgrade -y
RUN apt install golang-go vim -y
COPY test_files/test.ini /test.ini
COPY test_files/test.json /opt/test.json
COPY test_files/test.txt /usr/share/test.txt
COPY test_files/test.log /var/log/test.log
COPY test_files/test.html /home/test.html
WORKDIR /root/
COPY . /root/
WORKDIR /root/cmd
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -o reaperware
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -v -o reaperware_arm64
RUN CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -v -o reaperware.exe
RUN CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -v -o reaperware_arm64.exe
RUN CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -v -o reaperware_darwin
RUN CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -v -o reaperware_arm64_darwin