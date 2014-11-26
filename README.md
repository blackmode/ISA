ISA
===

POSTUP VYTVOŘENÍ REPA V KOMPLU:
1.) $ git init

2.)$ nano .git/config a pridat tam:

    [remote "origin"]
    
    url = git@github.com:blackmode/nameOfProject.git
    
    fetch = +refs/heads/*:refs/remotes/origin/*


3.) $ git pull origin master --> stazeni repa

4.) $ git commit -am "popis co ste udelali, nejakej kratkej"

5.) $ git push origin     --> nahrani souboru
