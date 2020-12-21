#include "testfunc.h"
#include <string>
#include <iostream>

int myfunction(){

	int x  = 0;
	depfunc(x);
	return x;
}

int main(){

	std::string v = "hallo";
	std::cout << v << std::endl;
	myfunction();
	return v[0];
}
