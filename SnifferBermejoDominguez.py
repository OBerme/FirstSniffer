import socket
import struct
#print(socket.gethostname())
#HOST = socket.gethostbyname(socket.gethostname())
#print(HOST)


#AF_INET //esto es el socket nose jajaja
#SOCK_RAW //no tiene protocolo especificado
#socket.IPPROTO_IP //El protocolo IP

# Crear un socket
#s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# Definir el host y el puerto
#HOST = '127.0.0.1'  # Dirección local o puedes poner la de google para escuchar todo
HOST = '192.168.1.132'
#HOST_GOOGLE = '142.250.200.68'
PORT = 12345        # Puerto arbitrario

# Enlazar el socket al host y puerto
#s.bind((HOST, PORT))

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
s.bind((HOST, PORT))

# Include IP headers
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# receive all packages
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

print("Esperando recibir datos...")
#print("Puerto {PORT}, ip {HOST}")
# Recibir dato s del socket

jump = 256 #Salto que permite pillar el siguiente byte

def printColumns(Datagrama,file):
    colum = ''
    for i in range(len(Datagrama)):
        # Join hasta cuatro elementos en una sola cadena separada por espacios
        colum = colum + str(Datagrama[i]) + ' '
        #Format the exit
        index = i+1
        if index % 4 == 0 :
            colum = colum + '   '
        if index % 16 == 0:
            print(colum, file=file)
            colum = ''

def Datos08ToDatos16(Datos08):
     if len(Datos08)% 2 == 1:                # ¿Es impar el número de bytes?
         Datos08 = Datos08+[0]              # Si el número de bytes es impar se añade un byte con valor 0x0
     Datos16 = []
     for i in range(0,len(Datos08),2):                  # Cada 2 bytes los almacena en una word de 16 bits
         Datos16.append(Datos08[i]*256+Datos08[i+1])    # Añadir a la lista Datos16 palabras de 2 bytes
     return Datos16

#Metodo que permite calcular si el checksum es correcto o no
def Checksum16(Datos16):
    Suma = sum(Datos16)
    #Corregir el acarreo
    Suma = (Suma//65536)+((Suma%65536))
    return 65535 - Suma


def seeTCP(DatagramaIP, file,ipOrigen, ipDestino,LongitudDatagramaTCP):
    longiReservaValues = DatagramaIP[12] #longitud y reservado bytes
    long = longiReservaValues >> 4 & 0x0F
    longCabeTCP = 20
    longCabeTCPActu = long*4
    
    if long != 5:
        Opciones = DatagramaIP[longCabeTCP:longCabeTCPActu]
        print("\tOpciones TCP:", Opciones, file=file)

    CabeceraTCP  = DatagramaIP[:longCabeTCPActu]
    print("\tCabeceraTCP:", CabeceraTCP, file=file)

    jump = 256 #Salto que permite pillar el siguiente byte,
    datosMessage = ["\tPuerto origen:", "\tPuerto destino:"]
    #Mostramos la informacion de la cabecera

    iPorts = 4 #Numeros de bytes que ocupan los puertos
    infoPuertos = []
    for i in range(0,iPorts,2):
        nInfo = CabeceraTCP[i]*jump + CabeceraTCP[(i+1)]
        infoPuertos.append(nInfo)
        print(datosMessage[int(i/2)], nInfo, file=file)

    #Sacamos los numeros de reconocimiento
    datosMessage = ["\tNumero secuencia:", "\tNumero reconocimiento:"]
    iNums = 12 #Index del los numeros
    sizeNum = 4 #Size of the next number
    infoNums = []
    for i in range(iPorts,iNums,sizeNum): #Damos saltos correspondientes a la anchura de los numeros
        nInfo = sum(CabeceraTCP[i] * (jump ** i) for i in range(sizeNum,0,-1))
        infoNums.append(nInfo)
        print(datosMessage[int((i-iPorts)/sizeNum)], nInfo, file=file)

    #Longitud datos
    print("\tLongitud cabecera TCP ", longCabeTCPActu, file=file)
    reserv = longiReservaValues  & 0x0F
    print("\tReservado : ", reserv, file=file)

    # Los flags se encuentran en el byte 13 (contando desde cero) y son los últimos 6 bits
    codeByte = CabeceraTCP[13] #campo con los flags de la cabecera
    flagsArrayMessage = []
    flags = []
    flagMessage = ["urg", "ack", "psh", "rst", "syn", "fin"]
    operaBit = 32

    for i in range(len(flagMessage)):
        # La operación AND para aislar cada bit
        flag = (codeByte & operaBit) != 0
        # Se agrega el resultado booleano a la lista
        if flag:
            flagsArrayMessage.append(flagMessage[i])
        flags.append(flag)
        # Se divide operaBit entre 2 usando división entera para obtener la máscara del siguiente bit
        operaBit //= 2

    print("\tFlags:", flagsArrayMessage,file=file)

    
    #Sacamos la ventana el checksum y el puntero a datos urgentes
    iWindowByte = 14    
    datosMessage = ["\tVentana :", "\tChecksum:", "\tPuntero datos urgentes:"]
    sizeNum = 2 #Size of the next number

    infoNums = []
    for i in range(iWindowByte,longCabeTCP,sizeNum): #Damos saltos correspondientes a la anchura de los numeros
        nInfo = CabeceraTCP[i]*jump + CabeceraTCP[(i+1)]
        infoNums.append(nInfo)
        actualI = int((i-iWindowByte)/sizeNum) #Indice sin sesgar, que va del 0-X
        if actualI != 1: #To avoid the checksum
            print(datosMessage[actualI], nInfo, file=file)
            

    #Calculo checksum
    print("\tChecksum:", file=file)
    #aniadimos el ip origen y destino
    DatagramaChecksum = []
    DatagramaChecksum.extend(ipOrigen)
    DatagramaChecksum.extend(ipDestino)
    #aniadimos el protocolo y el campo 6 
    DatagramaChecksum.extend([0,6,LongitudDatagramaTCP//jump, LongitudDatagramaTCP%jump]) 
    #Copiamos el datagrama TCP entero
    DatagramaChecksum.extend(DatagramaIP.copy()) 
    #Ponemos el checksum a 0
    DatagramaChecksum[28] = 0
    DatagramaChecksum[29] = 0

    CheckSumHex  = Datos08ToDatos16(DatagramaChecksum)
    FCheckSum = Checksum16(CheckSumHex)

    print("\t\tChecksum Calculado:", hex(FCheckSum), file=file)
    print("\t\tChecksum Original:", hex(infoNums[1]), file=file)

    if   infoNums[1] == FCheckSum or FCheckSum == 0:
        print("\t\tChecksum correcto!", file=file)
    else:
        print("\t\tChecksum INcorrecto!",file=file)


    if LongitudDatagramaTCP - ( longCabeTCPActu ) != 0 : 
        DatosTCP = DatagramaIP[longCabeTCPActu:] #Conseguimos los datos 
        print("\tDatos TCP:", file=file)
        printColumns(DatosTCP,file)
    else:
        print("\tWithout datos TCP",file=file)

    #aniadimos los


    #Convertimos los bytes en el mensaje correspondiente que esta mandado
    #if longDatosTCP != 0:
    #    DatosTCP = bytes(DatagramaIP[longCabeTCP:]) #Convertimos todo a bytes
    #    print("\tDatos TCP:", DatosTCP.decode('utf-8', errors='ignore'), file=file)
    #else:
    #    print("\tWithout datos TCP",file=file)


def seeICMP(DatosUDP, file):
    CabeceraICMP = DatosUDP[:8]
    print("\tCabeceraICMP:", CabeceraICMP, file=file)
    TypoICMP = CabeceraICMP[0]
    print("\tTypoICMP:", TypoICMP, file=file)
    if TypoICMP == 8:
        print("\tICMP Echo Request (solicitud de eco)", file=file)
    elif TypoICMP == 0:
        print("\tICMP Echo Reply (respuesta de eco)",file=file)
    elif TypoICMP == 11:
        print("\tICMP Time Exceeded (Tiempo excedido)",file=file)
    elif TypoICMP == 5:
        print("\tICMP Redirect (No se puede alcanzar el host)",file=file)

def seeUDP(DatagramaUDP, file, ipOrigen, ipDestino, LongitudDatagramaUDP):
    longCabeUDP = 8
    CabeceraUDP = DatagramaUDP[:longCabeUDP]
    
    print("\tCabeceraUDP:", CabeceraUDP, file=file)
    
    datosMessage = ["\tPuerto origen:", "\tPuerto destino:"
            ,"\tLongitud Datagrama:"]

    #Mostramos la informacion de la cabecera
    iCheckSum = longCabeUDP-2
    infoCabec = []
    for i in range(0,iCheckSum,2):
        nInfo = CabeceraUDP[i]*jump + CabeceraUDP[(i+1)]
        infoCabec.append(nInfo)
        print(datosMessage[int(i/2)], nInfo, file=file)

    #Checksum 
    CheckSum = CabeceraUDP[iCheckSum]*jump + CabeceraUDP[(iCheckSum+1)]
    #Ponemos el valores del Checksum a 0
    CheckDatagram = DatagramaUDP.copy()
    CheckDatagram[(iCheckSum)] = 0 
    CheckDatagram[(iCheckSum+1)] = 0

    CheckDatagram.extend([0,17,LongitudDatagramaUDP//jump, LongitudDatagramaUDP%jump]) 
    
    #Anaidimos los datos de la pseudocabecera
    CheckDatagram.extend(ipOrigen)
    CheckDatagram.extend(ipDestino)

    CheckSumHex  = Datos08ToDatos16(CheckDatagram)
    FCheckSum = Checksum16(CheckSumHex)
    
    print("\tChecksum:",file=file)
    print("\t\tChecksum Calculado", hex(FCheckSum), file=file)
    print("\t\tChecksum Original:", hex(CheckSum), file=file)

    if   CheckSum == FCheckSum or FCheckSum == 0:
        print("\t\tChecksum correcto!", file=file)
    else:
        print("\t\tChecksum INcorrecto!",file=file)

    # Miramos si tiene datos UDP
    if (LongitudDatagramaUDP - longCabeUDP) != 0: 
        # Mostrar datos UDP
        DatosUDP = DatagramaUDP[longCabeUDP:]  # Convertimos todo a bytes
        print("\t Datos UDP :", file=file)
        printColumns(DatosUDP,file)
    else:
        print("\t UDP Without data...", file=file)

        


def getIPFromData(Datagram, initIPDataga):
    ipSource = ''
    for i in range(initIPDataga,initIPDataga+3):
        ipSource += str(Datagram[i])+"."
    ipSource += str(Datagram[initIPDataga+3])
    return ipSource

def getIP(Datagrama, file):
    print("Datos IP",file=file)
    
    CabeceraIP = Datagrama[:20]
    print("CabecerIP: ", CabeceraIP, file=file)
    
    #La cabecera de la capa de red ocupa 14 bytes
    VersionIP = Datagrama[0] & 0xF0
    print("Version IP: ", VersionIP, file=file)
    #Mostramos la longitud del datagrama, que es la ultima parte del byte
    LongitudCabecera = Datagrama[0] & 0x0F
    print("LongitudCabecera: ", LongitudCabecera, file=file)
    indexDatos = 20 #Final zone where the optinal options dosen't exists

    Opciones = []
    if LongitudCabecera != 5:
        indexDatos = 60
        Opciones = Datagrama[20:60]
        DatosIP = Datagrama[60:]
    else: 
        DatosIP = Datagrama[20:]
    
    #Pillamos los dos bytes siguientes para la longitud de la trama
    LongitudDatagrama = Datagrama[2]*jump + Datagrama[3]
    print("LongitudTrama: ", LongitudDatagrama, file=file)
    
    #Pillamos los otros dos siguientes para el identificador
    IdentTrama = Datagrama[4]*jump + Datagrama[5]
    print("Identificador trama: ", IdentTrama, file=file)
    
    #Y otros dos mas que pillamos la fragmentacion
    #Fragmentacion
    #El primer bit es el de res y en la practica suele estar a cero
    #   El segundo y el tercero son los bits de No Fragment y More Fragments para 
    #   indicar que se puede cortar el paquete y si tiene mas compis detras que van a venir
    
    NF = (Datagrama[5] & 0b0100) != 0
    if not NF : 
        print("NOT FRAGMENT WARNING!", file=file)
            
    MF = (Datagrama[5] & 0b0010) != 0
    if not MF : 
        print("MORE FRAGMENTS WILL COME!", file=file)
        
    OffSetFragment = (Datagrama[5] & 0b0001) * jump + Datagrama[6]
    print("Off Set Fragmenta: ", OffSetFragment, file=file)
    
    #Sabemos que el datagrama IP envuelve a todos los demas datos de los protocolos
    #La cabecera IP ocupa 20 bytes
    TTL = Datagrama[8]
    print("TTL: ", TTL, file=file)
    
    #Mostramos el Protocolo
    protocolo = Datagrama[9]
    print("Protocolo: ", protocolo, file=file)

    #Calculo del checksum
    Checksum = CabeceraIP[10]*jump + CabeceraIP[11]

    #Ponemos el checksum a 0
    CabeceraIP[10] = 0
    CabeceraIP[11] = 0

    ChecksumHex = Datos08ToDatos16(CabeceraIP) #Pasamos a hexa
    print("Checksum", file=file)
    #CabeceraIPWCheck = CabeceraIP#Cabecera IP sin checksum

    ChecksumCalcula = Checksum16(ChecksumHex)
    print("\tChecksum Calculado", hex(ChecksumCalcula), file=file)
    print("\tChecksum Original:", hex(Checksum), file=file)

    if   Checksum == ChecksumCalcula or ChecksumCalcula == 0:
        print("\tChecksum correcto!", file=file)
    else:
        print("\tChecksum INcorrecto!",file=file)
        
    #Show the origin IP of the datagram
    initIPDataga = 12
    ipOrigen = getIPFromData(Datagrama, initIPDataga)
    print("IP Origen:", ipOrigen, file=file)
    
    #Show the destiny IP of the datagram
    initIPDataga = initIPDataga + 4
    ipDestino = getIPFromData(Datagrama, initIPDataga)
    print("IP Destino:", ipDestino, file=file)
    
    #Mostramos las opciones
    if len(Opciones) == 0:
        print("No tiene opciones extra", file=file)
    else:
        print("Opciones: ",Opciones, file=file)

    DatosIP = Datagrama[indexDatos:] #Get the Data before all the IP head
    #print("DatosIP", DatosIP, file=file)
    
    
    ipOriginBytes = CabeceraIP[12:16]
    ipDestiBytes = CabeceraIP[16:20]
    
    #Ahora mostramos los datos del protocolo en concreto
    if protocolo == 1: #Protocolo ICMP para saber si esta en pie el terminal
        print("Protocolo ICMP (", protocolo,")", file=file)
        seeICMP(DatosIP, file)
    elif protocolo == 6: #Protocolo TCP para establecer una conexion
        print("Datos del protocolo TCP (", protocolo,")", file=file)
        seeTCP(DatosIP,file,ipOriginBytes, ipDestiBytes, LongitudDatagrama-indexDatos)
    elif protocolo == 17: #Protocolo UDP para mandar daticos
        print("Datos del protocolo UDP (", protocolo,")", file=file)
        seeUDP(DatosIP,file,ipOriginBytes, ipDestiBytes, LongitudDatagrama-indexDatos)
    elif protocolo == 53: #Protocolo DNS para pedir direcciones de red
        #seeDNS(DatosIP,file)
        print("Datos del protocolo DNS (", protocolo,")", file=file)
    return True
    


with open('file_messages.txt', 'w') as file:
    i = 0
    maxMessages = 15
    while i < maxMessages:
        print('---------------------', file=file)
        print(file=file)
        data = s.recvfrom(65535)  # Buffer size para recibir datos
        # Convertir los datos recibidos a una lista de números decimales

        #decimal_data = [str(b) for b in data]
        # Imprimir en cuatro columnas

        Datagrama = list(data[0])
        print("Raw data datagram:", file=file)
        printColumns(Datagrama,file)   #Print the columns        
        if getIP(Datagrama,file) :
            i= i+1

    # Cerrar el socket
    s.close()
    print("Finished")



