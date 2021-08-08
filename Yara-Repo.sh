#!/usr/bin/env bash
RED='\e[31m'
NC='\033[0m'
clear

echo -e ${RED}' =============================\n'
echo -e '|      Yara repository        |\n'
echo -e '|-=-=-=-=-=-=-=-=-=-=-=-=-=-=-|\n'
echo -e '|       Version  0.0.1        |\n'
echo -e '|       Milad  Fadavvi        |\n'
echo -e '|     Git 2.28 or Higher      |\n'
echo -e '|   * Run script as Root *    |\n'
echo -e ' =============================\n\n'${NC}
sleep 10

mkdir /opt/yara-repo 2> /dev/null
cd /opt/yara-repo

rm -rf .git && git init && git remote add -f AlienVaultLabs https://github.com/AlienVault-Labs/AlienVaultLabs  > /dev/null && echo 'malware_analysis' >> .git/info/sparse-checkout && git config core.sparseCheckout true && git config pull.rebase false && git pull AlienVaultLabs master > /dev/null
wget -q https://gist.githubusercontent.com/pedramamini/c586a151a978f971b70412ca4485c491/raw/68ba7792699177c033c673c7ffccfa7a0ed5ce47/XProtect.yara 
rm -rf .git && git init && git remote add -f bamfdetect https://github.com/bwall/bamfdetect  > /dev/null && echo 'BAMF_Detect/modules/yara' >> .git/info/sparse-checkout && git config core.sparseCheckout true && git config pull.rebase false && git pull bamfdetect master > /dev/null
git clone -q https://github.com/bartblaze/Yara-rules bartblaze
rm -rf .git && git init && git remote add -f binaryalert https://github.com/airbnb/binaryalert  > /dev/null && echo 'rules/public' >> .git/info/sparse-checkout && git config core.sparseCheckout true && git config pull.rebase false && git pull binaryalert master > /dev/null
rm -rf .git && git init && git remote add -f CAPE  https://github.com/ctxis/CAPE  > /dev/null && echo 'data/yara/CAPE' >> .git/info/sparse-checkout && git config core.sparseCheckout true && git config pull.rebase false && git pull CAPE master > /dev/null
git clone -q https://github.com/CyberDefenses/CDI_yara CyberDefenses
git clone -q https://github.com/citizenlab/malware-signatures citizenlab
git clone -q https://github.com/stvemillertime/ConventionEngine stvemillertime
git clone -q https://github.com/deadbits/yara-rules deadbits
git clone -q https://github.com/eset/malware-ioc/ eset
rm -rf .git && git init && git remote add -f indicators https://github.com/fideliscyber/indicators  > /dev/null && echo 'yararules' >> .git/info/sparse-checkout && git config core.sparseCheckout true && git config pull.rebase false && git pull indicators master > /dev/null
rm -rf .git && git init && git remote add -f signature-base https://github.com/Neo23x0/signature-base  > /dev/null && echo 'yara' >> .git/info/sparse-checkout && git config core.sparseCheckout true && git config pull.rebase false && git pull signature-base master > /dev/null
wget -q https://gist.github.com/Neo23x0/f1bb645a4f715cb499150c5a14d82b44 && mv f1bb645a4f715cb499150c5a14d82b44 Neo23x0.yara
git clone -q https://github.com/fboldewin/YARA-rules fboldewin
git clone -q https://github.com/godaddy/yara-rules godaddy
git clone -q https://github.com/h3x2b/yara-rules h3x2b 
git clone -q https://github.com/SupportIntelligence/Icewater SupportIntelligence
git clone -q https://github.com/intezer/yara-rules intezer
git clone -q https://github.com/InQuest/yara-rules InQuest
git clone -q https://github.com/jeFF0Falltrades/YARA-Signatures jeFF0Falltrades
git clone -q https://github.com/kevthehermit/YaraRules kevthehermit
git clone -q https://github.com/Hestat/lw-yara Hestat
git clone -q https://github.com/tenable/yara-rules tenable
git clone -q https://github.com/tjnel/yara_repo tjnel
wget -q https://malpedia.caad.fkie.fraunhofer.de/api/get/yara/auto/zip && mv zip malpedia_auto_yar.zip && unzip malpedia_auto_yar.zip -d malpedia/  > /dev/null && rm -f malpedia_auto_yar.zip
git clone -q https://github.com/mikesxrs/Open-Source-YARA-rules OpenSourceYara
git clone -q https://github.com/prolsen/yara-rules prolsen
git clone -q https://github.com/advanced-threat-research/IOCs Adv-threat-research
git clone -q https://github.com/sophos-ai/yaraml_rules sophos
git clone -q https://github.com/reversinglabs/reversinglabs-yara-rules reversinglabs
git clone -q https://github.com/Yara-Rules/rules MainYaraRules
git clone -q https://github.com/fr0gger/Yara-Unprotect fr0gger
git clone -q https://github.com/Xumeiquer/yara-forensics Xumeiquer
fit clone -q https://github.com/malice-plugins/yara malice
wget -q https://raw.githubusercontent.com/VectraThreatLab/reyara/master/re.yar
rm -rf .git && git init && git remote add -f fsf https://github.com/EmersonElectricCo/fsf  > /dev/null && echo 'fsf-server/yara' >> .git/info/sparse-checkout && git config core.sparseCheckout true && git config pull.rebase false && git pull fsf master > /dev/null
rm -rf .git && git init && git remote add -f Cyber-Defence https://github.com/nccgroup/Cyber-Defence/  > /dev/null && echo 'Signatures/yara' >> .git/info/sparse-checkout && git config core.sparseCheckout true && git config pull.rebase false && git pull Cyber-Defence master > /dev/null
rm -rf .git && git init && git remote add -f malware-analysis https://github.com/SpiderLabs/malware-analysis  > /dev/null && echo 'Yara' >> .git/info/sparse-checkout && git config core.sparseCheckout true && git config pull.rebase false && git pull malware-analysis master > /dev/null
###
rm -rf .git && git init && git remote add -f ThreatHunting https://github.com/GossiTheDog/ThreatHunting > /dev/null && echo 'ThreatHunting' >> .git/info/sparse-checkout && git config core.sparseCheckout true && git config pull.rebase false && git pull ThreatHunting master > /dev/null
### From Awesome Community  
rm -rf .git && git init && git remote add -f TheSweeper-Rules https://github.com/Jistrokz/TheSweeper-Rules > /dev/null && echo 'yara' >> .git/info/sparse-checkout && git config core.sparseCheckout true && git config pull.rebase false && git pull TheSweeper-Rules main > /dev/null
git clone -q https://github.com/miladkahsarialhadi/RulesSet milad_kahsarialhadi
wget -q https://raw.githubusercontent.com/gil121983/obfuscatedPHP/master/obfuscatdPHP.yar
rm -rf .git && git init && git remote add -f binaryalert https://github.com/airbnb/binaryalert > /dev/null && echo 'rules/public' >> .git/info/sparse-checkout && git config core.sparseCheckout true && git config pull.rebase false && git pull binaryalert master > /dev/null && mkdir binaryalert-rules && mv rules/public/* binaryalert-rules && rm -rf rules/public/
rm -rf .git && git init && git remote add -f indicators https://github.com/fideliscyber/indicators> /dev/null && echo 'yararules' >> .git/info/sparse-checkout && git config core.sparseCheckout true && git config pull.rebase false && git pull indicators master > /dev/null && mv yararules fideliscyber
rm -rf .git && git init && git remote add -f red_team_tool_countermeasures https://github.com/fireeye/red_team_tool_countermeasures > /dev/null && echo 'rules' >> .git/info/sparse-checkout && git config core.sparseCheckout true && git config pull.rebase false && git pull red_team_tool_countermeasures master > /dev/null && mv rules red_team_tool_countermeasures 
git clone -q https://github.com/f0wl/yara_rules f0wl-rules
rm -rf .git && git init && git remote add -f fsf https://github.com/EmersonElectricCo/fsf > /dev/null && echo 'fsf-server/yara' >> .git/info/sparse-checkout && git config core.sparseCheckout true && git config pull.rebase false && git pull fsf master > /dev/null
git clone -q https://github.com/jeFF0Falltrades/YARA-Signatures jeFF0Falltrades
wget -q https://raw.githubusercontent.com/tylabs/qs_old/master/quicksand_exe.yara
wget -q https://raw.githubusercontent.com/tylabs/qs_old/master/quicksand_exploits.yara
wget -q https://raw.githubusercontent.com/tylabs/qs_old/master/quicksand_general.yara
git clone -q https://github.com/securitymagic/yara securitymagic
git clone -q https://github.com/StrangerealIntel/DailyIOC
git clone -q https://github.com/t4d/PhishingKit-Yara-Rules 
git clone -q https://github.com/x64dbg/yarasigs x64dbg_yarasigs
git clone -q https://github.com/thewhiteninja/yarasploit

###
clear
rm -rf .git
echo -e "Rules path: /opt/yara-repo\n"
echo "Number of YARA Rules: " && find . -name "*.yar*" -type f | wc -l && echo "Maybe contain duplicate rules in differnt Repo(s)!"
exit 0
