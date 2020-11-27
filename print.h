#ifndef PRINT_H
#define	PRINT_H

#include <stdint.h>     // e.g. uint64_t
#include <iostream>     // std::cout
#include <iomanip>      // std::setfill, std::setw

void print(unsigned char* c_data, size_t len){
    int l = 0;
	std::cout   << "data (" << len << " byte): " << std::endl << "\t"
                << sizeof(char) << " (char), " 
                << sizeof(int) << " (int), "
                << sizeof(size_t) << " (size_t), "
                << sizeof(long int) << " (long int), "
                << sizeof(uint64_t) << " (uint64_t), " << std::endl << "\t"
                << sizeof(float) << " (float), "
                << sizeof(double) << " (double), "
                << sizeof(long double) << " (long double)"
                << std::endl;
	for (size_t i=0; i<len; ++i) {
		if ((i%8)==0) {
            std::cout << std::endl << std::setfill(' ') << std::setw(4) << std::dec << l++ << ": ";
        }
		std::cout << "0x" << std::setfill('0') << std::setw(2) << std::hex << (int) c_data[i] << " ";
	}
	std::cout << std::dec << std::endl << std::endl;
    /*
    std::cout << "0b";
    for (size_t i=0; i<pad; ++i) {
        std::cout << std::bitset<8>((*b_out)[b+i]).to_string();
    }
    std::cout  << std::endl << "0b" << std::bitset<sizeof(int)*8>(rest).to_string() << std::endl;
    */
}

#endif
