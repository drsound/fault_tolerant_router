#!/usr/bin/env ruby
#encoding: UTF-8

#numero di volte che viene ritentato un ping che dà errore
#PING_RETRIES = 3
PING_RETRIES = 1

#numero di ip che devono essere pingati con successo per ritenere una linea funzionante
#REQUIRED_SUCCESSFUL_TESTS = 2
REQUIRED_SUCCESSFUL_TESTS = 4

#numero di secondi tra una verifica di tutte le linee e la successiva
PROBES_INTERVAL = 60

SEND_EMAIL = false
EMAIL_SENDER = "root@#{`hostname -f`.strip}"
EMAIL_RECIPIENTS = %w(utente@azienda.it)
SMTP_PARAMETERS = {
    :address => 'mail.azienda.it',
    #:port => 25,
    #:domain => 'azienda.it',
    #:authentication => :plain,
    #:enable_starttls_auto => false,
    :user_name => 'utente@azienda.it',
    :password => '12345678'
}

#LOG_FILE = '/var/log/route_monitor.log'
LOG_FILE = './route_monitor.log'

DEBUG = true
DRY_RUN = true

CONNECTIONS = [
    {
        :interface => 'eth1',
        :ip => '1.1.1.1',
        :gateway => '1.1.1.254',
        :description => 'Provider 1',
        #opzionale
        :weight => 1,
        #opzionale
        :default_route => false
    },
    {
        :interface => 'eth2',
        :ip => '2.2.2.2',
        :gateway => '2.2.2.254',
        :description => 'Provider 2',
        #opzionale
        :weight => 2,
        #opzionale
        #:default_route => false
    },
    {
        :interface => 'eth3',
        :ip => '3.3.3.3',
        :gateway => '3.3.3.254',
        :description => 'Provider 3'
        #opzionale
        #:weight => 3,
        #opzionale
        #:default_route => false
    }
]

TESTS = %w(
  208.67.222.222
  208.67.220.220
  8.8.8.8
  8.8.4.4
  4.2.2.2
  4.2.2.3
)

require 'rubygems'
require 'net/smtp'
require 'mail'
require 'logger'
logger = Logger.new(LOG_FILE, 10, 1024000)

def shuffle
  sort_by { rand }
end

def command(c)
  `#{c}` unless DRY_RUN
  puts "Comando: #{c}" if DEBUG
end

def set_default_route
  #individua le linee attive
  enabled_connections = CONNECTIONS.find_all { |connection| connection[:enabled] }
  #nessun bilanciamento se c'è una sola linea attiva
  if enabled_connections.size == 1
    nexthops = "via #{enabled_connections.first[:gateway]}"
  else
    nexthops = enabled_connections.collect do |connection|
      #il parametro weight nella descrizione delle linee è opzionale
      weight = connection[:weight] ? " weight #{connection[:weight]}" : ''
      "nexthop via #{connection[:gateway]}#{weight}"
    end
    nexthops = nexthops.join(' ')
  end
  #primo pacchetto di connessioni instaurate dall'interno
  command "ip route replace table 100 default #{nexthops}"
  #attiva le modifiche apportate alle tabelle di routing
  command 'ip route flush cache'
end

def ping(ip, source)
  if DRY_RUN
    sleep 0.1
    rand(2) == 0
  else
    `ping -n -c 1 -W 2 -I #{source} #{ip}`
    $?.to_i == 0
  end
end


#imposta tutte le linee come attive
CONNECTIONS.each do |connection|
  connection[:working] = true
  connection[:default_route] ||= connection[:default_route].nil?
  connection[:enabled] = connection[:default_route]
end

#ripulisci l'eventuale configurazione precedente (esagera per evitare problemi
#in caso di una variazione nel numero di interfacce tra un'esecuzione e l'altra)
10.times do |i|
  command "ip rule del priority #{39001 + i} &> /dev/null"
  command "ip rule del priority #{40001 + i} &> /dev/null"
  command "ip route del table #{1 + i} &> /dev/null"
end
command 'ip rule del priority 40100 &> /dev/null'
command 'ip route del table 100 &> /dev/null'

#disabilita "reverse path filtering" sulle interfacce riservate alle sole connessioni dall'esterno
command 'echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter'
CONNECTIONS.each do |connection|
  command "echo 2 > /proc/sys/net/ipv4/conf/#{connection[:interface]}/rp_filter"
end

#- pacchetti generati localmente ed aventi come sorgente l'ip di ethX
#- pacchetti di ritorno di connessioni instaurate dall'esterno su ethX
#- pacchetti 2...N di connessioni instaurate dall'interno per le quali il primo
#  pacchetto (tramite multipath routing) è stato inviato su ethX
CONNECTIONS.each_with_index do |connection, i|
  command "ip route add table #{1 + i} default via #{connection[:gateway]} src #{connection[:ip]}"
  command "ip rule add priority #{39001 + i} from #{connection[:ip]} lookup #{1 + i}"
  command "ip rule add priority #{40001 + i} fwmark #{1 + i} lookup #{1 + i}"
end
#primo pacchetto di connessioni instaurate dall'interno:
command 'ip rule add priority 40100 from all lookup 100'
set_default_route

loop do
  #per ogni linea...
  CONNECTIONS.each do |connection|
    #linea funzionante
    connection[:previously_working] = connection[:working]
    #linea abilitata
    connection[:previously_enabled] = connection[:enabled]
    connection[:successful_tests] = 0
    connection[:unsuccessful_tests] = 0
    #per ogni test (ordine casuale)...
    TESTS.shuffle.each_with_index do |test, i|
      successful_test = false
      #riprova diverse volte a pingare...
      PING_RETRIES.times do
        if DEBUG
          print "Linea #{connection[:description]}: ping #{test}... "
          STDOUT.flush
        end
        if ping(test, connection[:ip])
          successful_test = true
          puts 'ok' if DEBUG
          #evita altri ping allo stesso indirizzo dopo il primo positivo
          break
        else
          puts 'errore' if DEBUG
        end
      end
      if successful_test
        connection[:successful_tests] += 1
      else
        connection[:unsuccessful_tests] += 1
      end
      #se non stai già effettuando l'ultimo test...
      if i + 1 < TESTS.size
        if connection[:successful_tests] >= REQUIRED_SUCCESSFUL_TESTS
          puts "Linea #{connection[:description]}: evito altri test perché ci sono già sufficienti test positivi" if DEBUG
          break
        elsif TESTS.size - connection[:unsuccessful_tests] < REQUIRED_SUCCESSFUL_TESTS
          puts "Linea #{connection[:description]}: evito altri test perché ne sono rimasti troppo pochi disponibili" if DEBUG
          break
        end
      end
    end
    connection[:working] = connection[:successful_tests] >= REQUIRED_SUCCESSFUL_TESTS
    connection[:enabled] = connection[:working] && connection[:default_route]
  end

  #considera solo le connessioni che partecipano alla default route
  if CONNECTIONS.find_all { |connection| connection[:default_route] }.all? { |connection| !connection[:working] }
    CONNECTIONS.find_all { |connection| connection[:default_route] }.each { |connection| connection[:enabled] = true }
    puts 'Nessuna linea risulta funzionante, quindi le considero tutte funzionanti' if DEBUG
  end

  CONNECTIONS.each do |connection|
    description = case
                    when connection[:enabled] && !connection[:previously_enabled] then
                      ', riabilitata'
                    when !connection[:enabled] && connection[:previously_enabled] then
                      ', disabilitata'
                  end
    puts "Linea #{connection[:description]}: test superati #{connection[:successful_tests]}, falliti #{connection[:unsuccessful_tests]}#{description}"
  end if DEBUG

  #imposta una nuova default route se ci sono cambianti tra la vecchia e la nuova situazione
  set_default_route if CONNECTIONS.any? { |connection| connection[:enabled] != connection[:previously_enabled] }

  if CONNECTIONS.any? { |connection| connection[:working] != connection[:previously_working] }
    body = ''
    CONNECTIONS.each do |connection|
      body += "Linea #{connection[:description]}: #{connection[:previously_working] ? 'funzionante' : 'guasta'}"
      if connection[:previously_working] == connection[:working]
        body += "\n"
      else
        body += " --> #{connection[:working] ? 'funzionante' : 'guasta'}\n"
      end
    end

    logger.warn(body.gsub("\n", ';'))

    if SEND_EMAIL
      mail = Mail.new
      mail.from = EMAIL_SENDER
      mail.to = EMAIL_RECIPIENTS
      mail.subject = 'Variazione stato linee internet'
      mail.body = body
      mail.delivery_method :smtp, SMTP_PARAMETERS
      begin
        mail.deliver
      rescue Exception => ex
        puts "Problema invio email: #{ex}" if DEBUG
        logger.error("Problema invio email: #{ex}")
      end
    end
  end

  puts "Attendo #{PROBES_INTERVAL} secondi..." if DEBUG
  sleep PROBES_INTERVAL
end
