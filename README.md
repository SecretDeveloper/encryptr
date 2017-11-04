# Encryptr
Encryptr is a simple text and file encryption/decryption tool which uses RFC2898 (AES256).

[<img src="https://img.shields.io/appveyor/ci/secretdeveloper/encryptr/master.svg">](https://ci.appveyor.com/project/SecretDeveloper/encryptr)
[<img src="https://img.shields.io/nuget/v/encryptr.svg">](https://www.nuget.org/packages/encryptr/)


```
Encryptr 

Description:
    AES256 encryption tool.  Encrypted content is encoded as base64.    

Syntax:
The following argument prefix characters can be used: '-','/'
    --password, -p    
        The password used to encrypt and decrypt your content, do not 
        forget it or all is lost!
        Required, Default:''
        
    --text, -t    
        The text to be encrypted or decrypted.
        [Optional], Default:''
        
    --decrypt, -d    
        Decrypt flag
        [Optional], Default:''
        
    --input, -i    
        
        [Optional], Default:'Path to input FILE to be encrypted or decrypted.'
        
    --output, -o    
        
        [Optional], Default:'Path to output FILE where content will be 
        written,  if ommitted content is written to STDOUT.'
        

Examples:
    Encryption:
    encryptr 'mypassword' 'my content to encrypt'
    Decryption:
    encryptr 'mypassword' 'BASE64_STRING' -d
```


