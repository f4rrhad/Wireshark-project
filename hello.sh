# Capture network packets for 5 seconds and save to a file
sudo tshark -i any -a duration:5 -T fields -e ip.src -e ip.dst -e ip.proto -e frame.len -e udp > /Users/farhadsafi/Desktop/WireSharkPackets/example1.txt
# Navigate to the WireSharkPackets directory
cd WireSharkPackets
# Print the contents of example1.txt
echo "Src IP           Dst IP       Proto     Len     UDP port"
cat example1.txt


echo "******************************************************************************************"
echo "Suspicious Activity: packet size larger than 1000"
awk '$4> 1000 {print "Size:", $4, "Source IP:", $1, "Destination IP:", $2, "Protocol:", $3}' example1.txt



echo "******************************************************************************************"
echo "Suspicious Activity: Visited the destination more than 5 times"
awk '{ pair[$1,$2]++ } END { for (i in pair) if (pair[i] > 5) {split(i, arr, SUBSEP); print "Source IP:", arr[1], "visited Destination IP:", arr[2], pair[i], "times" } }' example1.txt

