#include<stdio.h>
#include<vector>
#include<string>

using namespace std;

class Solution {
public:
    string intToRoman(int num) {
        vector<pair<int,string>> p={{1000, "M"}, {900, "CM"}, {500, "D"}, {400, "CD"}, {100, "C"}, {90, "XC"}, {50, "L"}, {40, "XL"}, {10, "X"}, {9, "IX"}, {5, "V"}, {4, "IV"}, {1, "I"}};
        string roman="";
        for(int i=0;i<p.size();i++){
            while(p[i].first<=num){
                roman=roman+p[i].second;
                num=num-p[i].first;
            }
        }
        return roman;
    }
};

int main() {
    int inputs[] = {1, 4, 123, 5123, 123, 6345, 7481, 13231, 21, 12321, 12315};
    for (int i = 0; i < 11; i++) {
        Solution sol;
        auto output = sol.intToRoman(inputs[i]);
        printf("%s\n", output.c_str());
    }
}