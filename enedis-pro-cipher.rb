#!/usr/bin/ruby

# script ruby de déchiffrement et chiffremebt des pièces jointes envoyées par ENEDIS Enterprise
#  - ce logicel permet de convertir des données envoyées par ENEDIS Entreprise à ses clients par email
#  - le fichier est encodé avec le chiffrement AES/CBC-256
#  - il contient une entête de 128 bits (16 octets) suivi des données
#  - ce premier bloc est communément appelé IV (Initialisation Vector) : 
#
# auteur : Marc Quinton, mai 2021
# src: https://github.com/mqu/enedis-pro-cipher
#

# utilisation :
#  - actions supportées : dec (décode), enc (encodage), iv
#  - enedis-pro-cipher.rb enc key in out # decode in dans fichier out
#  - enedis-pro-cipher.rb enc key        # flux sur stdin, stdout
#  - enedis-pro-cipher.rb dec key in out 
#  - enedis-pro-cipher.rb dec key
#  - enedis-pro-cipher.rb iv in          # lit le bloc IV et l'affiche au format 32 caract. Hexa
#  - enedis-pro-cipher.rb test           # suite de tests.

# liens:
# - https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC
# - https://fr.wikipedia.org/wiki/Vecteur_d%27initialisation
# - https://www.enedis.fr/sites/default/files/Enedis-NOI-CF_107E.pdf


require 'openssl'  # gem install openssl

def trace msg
	STDERR.puts msg
end

class Utils
	def self.bin2hex(binary_string)
	  binary_string.unpack('H*').first
	end

	def self.hex2bin(str)
	  [str].pack "H*"
	end
end

class Crypto < Utils
  def initialize(key, iv, data, cipher='aes-256-cbc')
    @key = key
    @iv = iv
    @cipher = cipher
    @data = data
  end

  def encrypt
    c = OpenSSL::Cipher.new(@cipher).encrypt
    @iv = c.random_iv unless @iv
    c.iv = @iv 
    c.key = @key
    data = c.update(@data) + c.final
    return {
		:iv => @iv,
		:data => data
    }
  end 

  def decrypt
    c = OpenSSL::Cipher.new(@cipher).decrypt
    c.padding=0  # pas de padding pour le format ENEDIS
    c.iv = @iv
    c.key = @key
    c.update(@data) + c.final    
  end
end

class Enedis < Utils

  def self.decrypt_data key, _data
    # si la clé est fournie sous la forme de string, 32 caractères, 
    # elle est converti en binaire, 128 bits
    key = self.hex2bin(key) if(key.kind_of?(String) && 32 != key.bytesize)

	# la clé IV est dans les 16 premiers octets
	iv=_data[0..15]

	# le reste des données suit jusqu'à la fin du fichier
	data=_data[16..-1]

	# décodage de la data, format AES-CBC-256
	dec=Crypto.new(key,iv,data).decrypt
  end
  
  def self.iv _in
	return self.bin2hex(IO.binread(_in)[0..15])
  end

  def self.encrypt_file key, _in, _out, iv=nil
	data=IO.binread(_in)
	iv=self.hex2bin(iv) if iv
	aes=Crypto.new(self.hex2bin(key),iv,data)
	_data=aes.encrypt
	IO.binwrite(_out, _data[:iv]+_data[:data])
  end

  def self.decrypt_file key, _in, _out
	# lecture du fichier _in en mode binaire
	# dechiffrement de la data
	# ecriture en mode binaire dans _out
	IO.binwrite(_out, self.decrypt_data(key, IO.binread(_in)))
	trace "conversion #{_in} en #{_out}"
  end
end

class Test < Utils
	def initialize args
		cipher='aes-256-cbc'
		c = OpenSSL::Cipher.new(cipher)
		@key=c.random_key
		@iv=c.random_iv
	end
	
	def key
		@key
	end

	def iv
		@iv
	end

	def random_string size
		o = [('a'..'z'), ('A'..'Z')].map(&:to_a).flatten
		string = (0...size).map { o[rand(o.length)] }.join
	end

	def encode_data key, iv, data
		Crypto.new(self.key,iv,data).encrypt
	end

	def decode_data key, _data
		Enedis.decrypt_data key, _data
	end

	# KO. data != dec
	def run_test1
		data=random_string 256
		enc=encode_data @key, @iv, data
		dec=decode_data @key, data
		puts data
		puts dec
	end
	def run args
		run_test1
	end
end

def encode args
	case args.length

	when 1
		# mode pipe (stdin,stdout)
		trace "encode / pipe : fixme" ; exit 1
	when 3
		# args : key, in, out
		key = args[0]
		_in = args[1]
		_out = args[2]
		iv=nil
		Enedis.encrypt_file(key, _in, _out, iv)
	end
	
end

def decode args
	case args.length
	when 1
		key=args[0]
		data=STDIN.read
		# KO : ne fonctionne pas.
		# FIXME: error iv must be 16 bytes (ArgumentError) line 44
		dec=Enedis.decrypt_data(key, data)
		STDOUT.write(dec)
	when 3
		# decrypt args : key in-file out-file
		key=args[0]
		_in=args[1]
		_out=args[2]
		Enedis.decrypt_file(key, _in, _out)
	end
end

def iv file
	data=IO.binread(file)
	puts Enedis.bin2hex(data[0..15])
end

def _test args
	test = Test.new args
	test.run args
end

def usage
	puts "
usage:
 enedis-pro-cipher.rb action opts

 actions:
    dec key          OK
    dec key in out   OK
    enc key          KO
    enc key in out   OK
    iv in            OK
    test             : à compléter.

 - in, out sont des fichiers 
 - si les fichiers ne sont pas spécifiés, l'action est réalisée sur les fluxs stdin, stdout via des pipes
 - l'action iv permet d'extraire le bloc IV d'un fichier encodé au format hexa
 - formats
   - key: clé 256 bits - 32 octets binaire, 64 caractères hexa
   - iv: bloc IV (Initialisation Vector), 16 octets binaires, 32 octets hexa
   - les fichiers en provenance de Enedis-pro :
     - contiennent un bloc IV,
     - suivi des données encodées AES/CBC/256.
     - pour ce que j'en connais, le fichier décompressé est un ZIP 2.0 compatible 7zip.

links:
  - src: https://github.com/mqu/enedis-pro-cipher
  - doc: https://www.enedis.fr/sites/default/files/Enedis-NOI-CF_107E.pdf
  - java: décodeur java issu de la doc Enedis : https://gist.github.com/mqu/86b0671b4ac4c2dba54ae0f7a11e89bc
"

end

cmd=ARGV[0] ; ARGV.shift

case cmd
	when 'dec'
		decode ARGV
	when 'enc'
		encode ARGV
	when 'iv'
		iv ARGV[0]
	when 'test'
		_test ARGV[0]
	else
		usage
end
