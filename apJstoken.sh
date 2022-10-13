#!/usr/bin/env bash

figlet "ApJsToken-Tool"

printf "By:Bl@xkR@ven\n\n"

printf "Don't forget your URL like this 'https://www.example.com'\n"

echo "$(tput bold)Enter your URL here: " 
read url

echo -e "\n\e[1;36m[+] ApJsToken-Tool, Please wait..\e[0m"

gospider -s $url -a -w -r > ApJsToken.txt

echo -e "\n\e[1;36m[+] Filter data to Get JS files, Please wait..\e[0m"

cat ApJsToken.txt | grep -aEo 'https?://[^ ]+' | sed 's/]$//' | sort -u| grep -aEi '\.(js)' > Js_onfilter.txt

rm -f ApJsToken.txt

echo -e "\n\e[1;36m[+] Search to find  API,TOKENS , Please wait..\e[0m"

nuclei -l Js_onfilter.txt -t ~/.local/nuclei-templates/exposures/tokens/generic/

echo -e "\n\e[1;36m[+] Advanced search, Please wait..\e[0m"

nuclei -l Js_onfilter.txt -t ~/.local/nuclei-templates/token-spray > Lastfilter.txt 

printf "\n\n"

echo "$(tput bold)Thanks for use ApJsToken-Tool ... Follow me on Twitter @MohsenJamall" 
