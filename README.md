windows
gcc -o [.exe file name] capture_packet.c -lwpcap -lws2_32  -I "[WpdPack path]\WpdPack_4_1_2\WpdPack\Include"

linux
 gcc -o [.exe file name] capture_packet.c -lpcap
