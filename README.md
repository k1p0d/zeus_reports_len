# zeus_reports_len
This exploit is a remote timing attack against Zeus C&C enabling the attacker to resolve the length in characters of the reports directory name by carefully measuring the response time of the server.
 -Rotem Kerner

# Whats in the box ?

* zeus_reports_dirlen.php - is the actual remote timing attack exploit which reveals the reports directory name length<br>
* zeus_rc4_algo_brute.php - as the name suggests, when given the right encryption key this tool lets you brute force
the algorthim if it has the right cipher in its repository.<br>
* Zeus.class.php - a generic Zeus client class which is able to communicate with most zeus variants<br>
* Encryption.class.php - the cipher repository class, contains different variants of encryption ciphers used in zeus<br>

# TODO
* optimize the sampling stage
* optimize the "mesurable interval test"
* Threading
* recode in python?

