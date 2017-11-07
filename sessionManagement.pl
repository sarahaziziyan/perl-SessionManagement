#!/usr/bin/perl -w
use strict;
use warnings;
use CGI;
use Fcntl;
use CGI::Session;
use CGI::Carp;
use epgFormReturnJsCss qw(epgFormReturnJsCss epgFormReturnJsCssLogin);
use commonFunctions qw(packUnpack systemTime);
use Crypt::SaltedHash;
use PDBC;
binmode STDOUT, ":utf8";

############# Version 1.3 ###############
####### Last modified 11/05/2017 ########
######## Author : Sarah Aziziyan ########

use constant TRUE  => 1;
use constant FALSE => 0;

use constant TRIAL_CONST    => 3;
use constant REDIRECTCODE   => 302;
use constant IDLE_TIME_EXPIRATION  => 30; ## in seconds ##
use constant TOTAL_TIME_EXPIRATION => 60; ## in seconds ##

sub getOrCreateSession{
  my $cgi     = shift;
  my $method  = $cgi->param("method");
  my $session = new CGI::Session(undef, $cgi, {Directory=>'/tmp/'});
  setAccessTime($session,$method);
  if(checkForExpiration($session)){ ## it has been expired
    return undef;
    $session->flush();
    $session->delete();
  }else{
    return $session;
  }  
}

sub setAccessTime{
  my $session = shift;
  my $method  = shift;
  my %excludedMethods=do "/var/www/config/excludedMethods.cfg";
  if(!defined($excludedMethods{$method})){
    $session->param("accessTime",time);
  }
}

sub checkForExpiration{
  my $session       = shift;
  my $currentTime   = time;
  my $accessTime    = $session->param("accessTime");
  my $creationTime  = $session->ctime();
  open(TEST, ">>/tmp/sessionManagement");
  print TEST "accessTime=$accessTime\ncreationTime=$creationTime\ncurrentTime=$currentTime\n";
  close(TEST);
  if(checkSessionIdleTimeExpiration($accessTime,$currentTime)){
    return TRUE;
  }else{
    if(checkSessionTotalTimeExpiration($creationTime,$currentTime)){
      return TRUE;
    }else{
      return FALSE;
    }
  }  
}

sub checkSessionIdleTimeExpiration{
  my $accessTime  = shift;
  my $currentTime = shift;
  {
    use bigint;
    my $difference = $currentTime - $accessTime;
    open(TEST, ">>/tmp/sessionManagement");
    print TEST "IdleTimeExpiration=$difference\n";
    close(TEST);
    if($difference>IDLE_TIME_EXPIRATION){
      return TRUE;
    }else{
      return FALSE;
    }
  }
}

sub checkSessionTotalTimeExpiration{
  my $creationTime = shift;
  my $currentTime  = shift;
  {
    use bigint;
    my $difference = $currentTime - $creationTime;
    open(TEST, ">>/tmp/sessionManagement");
    print TEST "TotalTimeExpiration=$difference\n";
    close(TEST);
    if($difference>TOTAL_TIME_EXPIRATION){
      return TRUE;
    }else{
      return FALSE;
    }
  }
}

sub checkIfUserIsLocked{
  my $cgi      = shift;
  my $database = shift;
  my $username = $cgi->param("username");
  my $locked;
  print TEST "username:$username\n";
  $database->query("select locked from userAccounts where username=?");
  $database->params([$username]);
  if($database->selectFromDatabase()){
    my $resultArray = $database->resultArray();
    if($#{$resultArray}==0){
      ($locked) = @{$resultArray->[0]};
      print TEST "locked=$locked\n";
    }else{
      $locked = FALSE;
    }
    return $locked;
  }
  return FALSE;
}

sub sayUserIsLocked{
  my $cgi     = shift;
  my $session = shift;
  setLoginFlag($session,FALSE);
  return packUnpack "کاربری مربوطه به علت 3 بار اشتباه در کلمه عبور مسدود میباشد.";
}

sub checkLoginTrials{
  my $session = shift;
  my $trials  = shift;
  if($trials > TRIAL_CONST){
    return TRUE;
  }else{
    return FALSE;
  }
}

sub setUserToLockedState{
  my $cgi      = shift;
  my $database = shift;
  my $username = $cgi->param("username");
  my $locked   = TRUE;
  my ($lockTime,$lockDate) = systemTime();
  $database->query("update userAccounts set locked=?,lockDate=?,lockTime=? where username=?");
  $database->params([$locked,$lockDate,$lockTime,$username]);
  if($database->insertAndUpdateAndDeleteDatabase()){
    $database->commit();
  }else{
    $database->rollback();
  }
  print TEST "code=".$database->code.",msg=".$database->msg."\n";
  print TEST "\n-----user lock updated-------\n";
  ## if code!=0 log into file is nessesary
}

sub authenticate{
  my $cgi      = shift;
  my $database = shift;

  my $username = $cgi->param("username");
  my $password = $cgi->param("password");
  
  $database->query("select psw from userAccounts where username=?");
  $database->params([$username]);
  if($database->selectFromDatabase()){
    my $resultArray = $database->resultArray(); 
    if($#{$resultArray}==0){
      my ($psw) = @{$resultArray->[0]};
      $psw = "{SSHA256}".$psw;
      if (Crypt::SaltedHash->validate($psw, $password)) {
        print TEST "<<authenticated>>\n";
        return TRUE;
      }
    }
  }
  print TEST "[authenticate] code=".$database->code.",msg=".$database->msg.",query=".$database->query.",params=".@{$database->params}."\n";
  return FALSE;
}

sub loginSuccessful{
  my $cgi     = shift;
  my $session = shift;
  setLoginFlag($session,TRUE);
  #redirectToNextPage($cgi);
  my ($code,$content) = myNextPage($cgi);
  return ($code,$content);
}

sub redirectToNextPage{
  my $cgi     = shift;
  print $cgi->header(-location => q[http://192.168.1.220/cgi-bin/epgForm.pl], -status=>301);
  #print $cgi->header(-type=>'text/html',-charset=>'utf-8');
  return "nextPage";
}

sub plusTrials{
  my $session = shift;
  my $trials  = shift;
  $session->param("~login-trials", ++$trials);
  setLoginFlag($session,FALSE);
}

sub setLoginFlag{
  my $session   = shift;
  my $loginFlag = shift;
  $session->param("~logged-in",$loginFlag);
}


##-----------------------##
sub login{
  my $cgi        = shift;
  my $session    = shift;
  my $trials     = $session->param("~login-trials") || 1;
  my $printValue = "";
  my $code = 0;
  open(TEST,">>/tmp/sessionManagement");
  print TEST "in login\n";
  print TEST "trials:$trials\n"; 
  my $database = new PDBC(name=>"payment");
  if($database){
    if(checkIfUserIsLocked($cgi,$database)){
      $printValue = sayUserIsLocked($cgi,$session);
      print TEST "user is locked\n";
      ## delete this session
    }else{
      
      if(checkLoginTrials($session,$trials)){
        print TEST "too much trials\n";
        setUserToLockedState($cgi,$database);
        $printValue = sayUserIsLocked($cgi,$session);
    #     ## delete this session
      }else{
        print TEST "trials ok\n";         
        if(authenticate($cgi,$database)){
          ($code,$printValue) = loginSuccessful($cgi,$session);
        }else{
          plusTrials($session,$trials);
          $printValue = packUnpack "نام کاربری یا کلمه عبور اشتباه است.";
        }
      }
      print TEST "no locked\n";
    }
    $database->disconnect();
  }else{
    
    print TEST "dbCode=".PDBC::code."\n";
    print TEST "dbMsg=".PDBC::msg."\n";
    
  }
  close(TEST);
  my $cookie = $cgi->cookie(CGISESSID => $session->id) || $cgi->param('CGISESSID') || undef;
  print $cgi->header(-type=>'text/xml',-charset=>'utf-8',-cookie=>$cookie);
  print "<info><code>$code</code><mydata><![CDATA[$printValue]]></mydata></info>";
}

sub sayHi{
  my $cgi = shift;
  print $cgi->header(-type=>"text/xml", -charset=>'utf-8');
  print "<info><code></code><mydata>hi</mydata></info>";
}

sub sayBye{
  my $cgi = shift;
  print $cgi->header(-type=>"text/xml", -charset=>'utf-8');
  print "<info><code></code><mydata>bye</mydata></info>";
}

sub myNextPage{
  my $cgi      = shift;
  my $username = $cgi->param("username");
  my $nextPage = "<!DOCTYPE html>
                    <html>
                      <head>
                        <script type='text/javascript' charset='utf8' src='/js/jquery-1.11.3.min.js'></script>
                        <script>
                          function callMethod(method_){
                            
                            \$.post('/cgi-bin/sessionManagement.pl',
                              {
                                method   : method_
                              },
                            function(data, status){
                              var xml = \$(data);
                              var myCode = xml.find('code').text();
                              var mydata = xml.find('mydata').text();
                              if(myCode == '0'){
                                alert(mydata);
                              }else if(myCode==".REDIRECTCODE."){
                                document.write(mydata);
                                document.close();                                
                              }else{
                                alert(mydata);
                              }
                            });
                          }        
                        </script>
                      </head>
                      <body>
                        <h1>This is the next page</h1>
                        <h2>hello $username</h2>
                        <button onClick='callMethod(\"sayHi\")'>sayHi</button>
                        <button onClick='callMethod(\"sayBye\")'>sayBye</button>
                      </body>
                    </html>";
  return (REDIRECTCODE,$nextPage);
}

sub  showLoginPage {
  my $cgi = shift;
  my $redirectOrNot = shift;

  ##Pack UnPack constants##
  my $titlePack         = packUnpack "سامانه دریافت و پرداخت الکترونیک بیمه ایران";
  my $usernameLabelPack = packUnpack "نام کاربری";
  my $passwordLabelPack = packUnpack "کلمه عبور";

  
  my $loginPageContent = "
  <!DOCTYPE html> 
    <head>
      <script type='text/javascript' charset='utf8' src='/js/jquery-1.11.3.min.js'></script>
      <script>
        \$(document).ready(function(){
          if($redirectOrNot){
            alert('session expired!');
          }
        })
        function login(){
            var username_ = \$('#username').val();
            var password_ = \$('#password').val();
            \$.post('/cgi-bin/sessionManagement.pl',
              {
                method   : 'login',
                username : username_,
                password : password_
              },
            function(data, status){
              var xml = \$(data);
              var myCode = xml.find('code').text();
              var myMsg = xml.find('msg').text();
              var mydata = xml.find('mydata').text();
              if(myCode == '0'){
                alert(mydata);
              }else if(myCode==".REDIRECTCODE."){
                document.write(mydata);
                document.close();
              }else{
                alert(mydata);
              }
            });
        }
      </script>
    </head>
    <body>
      username : <input type='text' id='username'></input><br/>
      password : <input type='text' id='password'></input><br/>
      <button id='myBtn' onClick='login()'>login</button>
    </body>
  </html>";

  my $headerType = "text/html";
  if(defined($redirectOrNot)){
    if($redirectOrNot==TRUE){
      $headerType = "text/xml";
      print $cgi->header(-type =>$headerType,-charset=>'utf-8');
      print "<info><code>".REDIRECTCODE."</code><mydata><![CDATA[".$loginPageContent."]]></mydata></info>";
    }else{
      print $cgi->header(-type =>$headerType,-charset=>'utf-8');
      print $loginPageContent;
    }
  }else{
    print $cgi->header(-type =>$headerType,-charset=>'utf-8');
    print $loginPageContent;
  }


}

sub main{
  
  my $cgi       = new CGI;
  my $method    = $cgi->param("method");
  my $loggedIn  = 0;

  

  my $session   = getOrCreateSession($cgi);
  if(defined $session){
    
    if(defined $session->param("~logged-in")){
      $loggedIn = $session->param("~logged-in");
    }    

    open(TEST, ">>/tmp/sessionManagement");
    print TEST "--------------------------\n";
    print TEST "sessionId=".$session->id."\n";
    print TEST "loggedIn=$loggedIn\n";
    close(TEST);
  }
    
  if(defined($method)){
    if($method eq "login"){
      login($cgi,$session);
    }
    elsif($loggedIn){
      if($method eq "sayHi"){
        sayHi($cgi);
      }elsif($method eq "sayBye"){
        sayBye($cgi);
      }
    }else{ ## user is not logged-in redirect to login page
      showLoginPage($cgi,TRUE); ##??? hamoon session ro bede behesh ???
    }
  }else{ ## user is not logged-in redirect to login page
    showLoginPage($cgi,FALSE);
  }
  
}

main();