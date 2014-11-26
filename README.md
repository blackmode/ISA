ISA
===

Jak rozjet git pod linuxem:
nainstalujete git
nastavte si ssh-key na githubu, navod najdete na googlu
vyvorite si slozku nekde: $ mkdir ifj_project $ cd ifj_project

POSTUP VYTVOŘENÍ REPA V KOMPLU:
1.) vytvorite repozitar: $ git init
2.) otevrete soubor config: $ vim .git/config pridate tam:
    [remote "origin"]
    url = git@github.com:BigTony/ifj2013.git
    fetch = +refs/heads/*:refs/remotes/origin/*

3.) pak by melo stacit uz jen dat $ git pull origin mastera melo by to vse stahnout
4.) kdyz udelate nejaky zmeny tak date $ git commit -am "popis co ste udelali, nejakej kratkej"
5.) a pak $ git push origin 
