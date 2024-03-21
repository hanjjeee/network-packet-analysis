<strong>windows</strong></br>
gcc -o [.exe file name] capture_packet.c -lwpcap -lws2_32 -I "[WpdPack path]\WpdPack_4_1_2\WpdPack\Include"

<strong>linux</strong></br>
 gcc -o [.exe file name] capture_packet.c -lpcap -lcurl</br>
(Remove winsocket.h header file declaration.)
