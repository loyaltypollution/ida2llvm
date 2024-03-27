FROM debian:stable-20230320-slim

# Global: ignore TLS errors
ENV CURL_CA_BUNDLE=""
ENV PYTHONWARNINGS="ignore:Unverified HTTPS request"
RUN echo 'Acquire::https::Verify-Peer "false";' > /etc/apt/apt.conf.d/99-cert

# Install prerequisites
RUN apt-get update --fix-missing && \
    DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        inotify-tools \
        sudo \
        wget && \
    rm -rf /var/lib/apt/lists/*

COPY .devcontainer/certs/ /usr/local/share/ca-certificates/
RUN update-ca-certificates

# Install wine
ARG DEBIAN_FRONTEND=noninteractive
RUN dpkg --add-architecture i386 && \
    mkdir -pm755 /etc/apt/keyrings && \
    wget --no-check-certificate --output-document /etc/apt/keyrings/winehq-archive.key https://dl.winehq.org/wine-builds/winehq.key && \
    wget --no-check-certificate -NP /etc/apt/sources.list.d/ https://dl.winehq.org/wine-builds/debian/dists/bullseye/winehq-bullseye.sources

RUN apt-get update --fix-missing && \
    DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends \
        winehq-stable \
        xvfb && \
    rm -rf /var/lib/apt/lists/*

# Prevents the popup to install mono
# https://superuser.com/questions/948508/how-to-disable-gecko-package-popup-for-wine
ENV WINEDLLOVERRIDES="mscoree,mshtml="

# Ensure that registry change is flushed from registry onto disk
# https://serverfault.com/questions/1082578/wine-in-docker-reg-add-only-keeps-effects-temporarily
RUN wine reg add "HKEY_CURRENT_USER\Software\Wine" /v Version /t REG_SZ /d win10 /f && \
    while [ ! -f ~/.wine/user.reg ]; do sleep 1; done

# Install python
# Note that Python 3.10 requires wine to emulate Windows 10
ARG PYTHON_URL=https://www.python.org/ftp/python/3.10.0/python-3.10.0-amd64.exe
ARG PYTHON_DIR="C:\\Program Files\\Python310"
RUN Xvfb :0 -screen 0 1024x768x16 & \
    wget --quiet --no-check-certificate "${PYTHON_URL}" --output-document \
        python_installer.exe && \
    DISPLAY=:0 wine python_installer.exe \
        /quiet \
        InstallAllUsers=1 \
        PrependPath=1 && \
    rm python_installer.exe

# Download python dependencies on Wine-Python
COPY .devcontainer/dep/requirements.txt ./requirements.txt
RUN WINEPATH="${PYTHON_DIR}" wine python -m pip install -r requirements.txt && \
    rm -rf requirements.txt

# Copy IDA over
ADD .devcontainer/dep/ida.tar ~/.wine/ida

# Accept IDA EUA and set Python's version via registry
RUN wine reg add "HKEY_CURRENT_USER\Software\Hex-Rays\IDA" /v Python3TargetDLL /t REG_SZ /d "${PYTHON_DIR}/python3.dll" /f && \
    wine reg add "HKEY_CURRENT_USER\Software\Hex-Rays\IDA" /v "License Think-Cell Operations GmbH" /t REG_DWORD /d 1 /f && \
    while inotifywait -e modify ~/.wine/user.reg; do sleep 1; done

# Install LLVM using pre-built apt.llvm.org packages
RUN wget -O- https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --dearmor | sudo tee /usr/share/keyrings/llvm.gpg \
    && echo """deb [signed-by=/usr/share/keyrings/llvm.gpg] http://apt.llvm.org/bullseye/ llvm-toolchain-bullseye-16 main \
    deb-src http://apt.llvm.org/bullseye/ llvm-toolchain-bullseye-16 main""" >> /etc/apt/sources.list
 
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends clang-16 libclang-16-dev llvm-16-dev graphviz \
    && apt-get -y autoremove \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir /home/bin2llvm
WORKDIR /home/bin2llvm

COPY ida2llvm /home/bin2llvm/ida2llvm/
COPY run.sh /home/bin2llvm/run.sh
COPY docker_entrypoint.py /home/bin2llvm/docker_entrypoint.py
ENTRYPOINT ["/home/bin2llvm/run.sh"]