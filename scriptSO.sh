#!/bin/bash

#Functie pentru a verifica caracteristicile periculoase ale unui fisier
check_file() {
    file="$1"
    result="SAFE"

    #Verificam daca fisierul are mai putin de 3 linii
    nr_linii=$(wc -l < "$file")
    if [ "$num_linii" -lt 3 ]; then
        #Verificam numarul de cuvinte si caractere
        num_cuv=$(wc -w < "$file")
        num_car=$(wc -m < "$file")
        if [ "$num_cuv" -gt 1000 ] && [ "$num_car" -gt 2000 ]; then
            echo "$file" #Fisierul este suspect
            return
        fi
    fi

    #Verificam daca fisierul contine caractere non-ASCII sau cuvinte cheie asociate fisierelor periculoase
    if grep -qP "[^\x00-\x7F]" "$file" || grep -qE "corrupted|dangerous|risk|attack|malware|malicious" "$file"; then
        echo "$file" #Fisierul este suspect
        return
    fi

    echo "$result" #Fisierul este sigur
}

#Verificam fisierul si transmitem rezultatul prin pipe
result=$(check_file "$1")
echo "$result"
