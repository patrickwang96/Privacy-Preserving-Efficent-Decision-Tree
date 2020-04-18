sudo apt-get update
sudo apt-get install build-essential libgmp3-dev vim iperf
sudo apt install cmake libeigen3-dev

git clone https://github.com/ladnir/relic.git
git clone --recursive https://github.com/osu-crypto/libOTe.git
# git clone https://github.com/patrickwang96/Privacy-Preserving-Efficent-Decision-Tree.git

cd relic
cmake . -DMULTI=OPENMP
make -j4
sudo make install

cd ../libOTe/cryptoTools/thirdparty/linux
bash all.get

cd ../../..
cmake . -DENABLE_MIRACL=ON -DENABLE_RELIC=ON -DENABLE_ALL_OT=ON

# make sure disabled the simplest ot and simplestot asm

cmake . -DENABLE_SIMPLESTOT=OFF -DENABLE_SIMPLESTOT_ASM=OFF
make -j4

cd ../Privacy-Preserving-Efficent-Decision-Tree/
cmake .
make -j4 client server