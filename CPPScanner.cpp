#include <iostream>
#include <map>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>

std::map<int, std::string > serviceMap = {

	{21, "FTP"}, 
	{22, "SSH"}, 
	{23, "TELNET"}, 
	{25, "SMTP"}, 
	{53, "DNS"}, 
	{80, "HTTP"}, 
	{110, "POP3"}, 
	{143, "IMAP"}, 
	{443, "HTTPS"}, 
	{3389, "RDP"}, 

};

std::string getServiceName(int port) {

if (serviceMap.count(port))
	return serviceMap[port];
	return "DESCONHECIDO";

};

int main(){

	std::cout << "----------MUNHOZ SCANNER----------" << '\n';
	std::string ip;
	std::cout << "Enter target IP:" << '\n';
	std::cin >> ip;
	std::cout << "Enter scan interval (seconds): " << '\n';
	int time;
	std::cin >> time;
	std::cout << "Enter number of ports: " << '\n';
	int numberOfPorts;
	std::cin >> numberOfPorts;

	for(int port = 1; port <= numberOfPorts; port++) {
	int sock = socket(AF_INET, SOCK_STREAM, 0);

	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

	int result = connect(sock, (sockaddr*)&addr, sizeof(addr));

	
	if(result == 0) {
		std::cout << "Porta aberta: " << port << " " <<  getServiceName(port) << '\n';
	}

	close(sock);

	sleep(time);

}

}
