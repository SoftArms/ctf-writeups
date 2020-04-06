# angstromCTF

Enlace: https://ctf.auburn.edu/

Fechas: 4 a 5 de abril

-----------------------------------

## Signals




### FCC Hunter

Parece que debemos encontrar la frecuencia que utilizan los autobuses de un servicio de la universidad que se llama Tiger Transit:

![image](images/Screenshot_4.jpg)

Finalmente encontramos la web https://www.radioreference.com/:

![image](images/Screenshot_5.jpg)

Comprobando las frecuencias de la zona universitaria vemos que hay una para los autobuses:

![image](images/Screenshot_6.jpg)



  

### Digital

Tenemos que obtener el mensaje de un audio:

![image](images/Screenshot_7.jpg)

Utilizando fldigi probamos varias opciones hasta que se descubre que es una señal en BPSK-63:

![image](images/Screenshot_8.jpg)

Y se obtiene la flag en una de estas frecuencias:

![image](images/Screenshot_9.jpg)


-----------------------------------

## Password cracking




### Mental

Parece que la contraseña podría ser el MD5 de concatenar Color-País-Fruta:

![image](images/Screenshot_21.jpg)

Se descarga una lista de palabras de colores, países y frutas y se prueba con un script de Python:

![image](images/Screenshot_22.jpg)

Y se obtiene rápidamente el valor:

![image](images/Screenshot_23.jpg)



### Manager

Se parte de un Keepass con contraseña:

![image](images/Screenshot_24.jpg)

Como se sabe que la contraseña son solo números, se puede crackear con:

```
hashcat64.exe -m 13400 -a 3 -O -w 3 manager.hash -i -1 ?d ?1?1?1?1?1?1?1?1
```

![image](images/Screenshot_25.jpg)

![image](images/Screenshot_26.jpg)

Simplemente abrimos el Keepass y se obtiene la flag:

![image](images/Screenshot_27.jpg)


  
### Salty

Es un hash con su salt:

![image](images/Screenshot_13.jpg)

Se prueban distintas opciones de hashcat:

![image](images/Screenshot_14.jpg)

Hasta que se consigue crackear con una de estas:

![image](images/Screenshot_15.jpg)


  
### Zippy

Se trata de ficheros zip dentro de otros ficheros zip, todos con contraseña. Simplemente usando zip2john (de John the ripper) se pueden obtener las contraseñas:

![image](images/Screenshot_16.jpg)

  

### Big Mac

Es un hash sin salt:

![image](images/Screenshot_17.jpg)

Podría ser un SHA-1:

![image](images/Screenshot_18.jpg)

En hashcat llaman la atención los de HMAC-SHA1 por el título:

![image](images/Screenshot_19.jpg)

Y se puede crackear con 

```
hashcat -a 0 -O -w 3 -m 160 sha1.txt /usr/share/wordlists/rockyou.txt --force
```

-----------------------------------

## Forensics



### Har har har

Primero vemos qué es el fichero:

![image 1](images/Screenshot_1.jpg)

De [la Wikipedia](https://es.wikipedia.org/wiki/.har), tenemos que el formato HTTP Archive o HAR, es un formato de un fichero de archivo en formato JSON, para el registro de la interacción de un navegador web con un sitio. La extensión común para estos archivos es .har.

De hecho parece que contienen una imagen en base64:

![image](images/Screenshot_2.jpg)

La abrimos en línea y tenemos la flag:

![image](images/Screenshot_3.jpg)

  


### mobile0

Debemos encontrar una flag en un fichero IPA:

![image](images/Screenshot_10.jpg)

Lo descomprimimos como si fuera un zip:

![image](images/Screenshot_11.jpg)

Y se encuentra rápidamente:

![image](images/Screenshot_12.jpg)
