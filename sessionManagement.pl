#!/usr/bin/perl -w
use strict;
use warnings;
use CGI;
use Fcntl;
use CGI::Session;
use CGI::Carp;
use epgFormReturnJsCss qw(epgFormReturnJsCss epgFormReturnJsCssLogin);
use commonFunctions qw(packUnpack);

sub signInOut {
  my ($cgi) = @_;  
  

  ##Pack UnPack constants##
  my $titlePack         = packUnpack "سامانه دریافت و پرداخت الکترونیک بیمه ایران";
  my $usernameLabelPack = packUnpack "نام کاربری";
  my $passwordLabelPack = packUnpack "کلمه عبور";

  print $cgi->header(-type =>'text/html',-charset=>'utf-8');
  print <<EOF;
  <!DOCTYPE html> 
    <head>
      <script type='text/javascript' charset='utf8' src='/js/jquery-1.11.3.min.js'></script>
      <script>
        \$(document).ready(function(){
          
        })
        function step1Click(){
            var username_ = \$("#username").val();
            var password_ = \$("#password").val();
            \$.post("/cgi-bin/sessionManagement.pl",
              {
                method      : "login",
                lg_username : username_,
                lg_password : password_
              },
            function(mydata, status){
              alert(mydata);
            });
        }
        function step2Click(){
            var username_ = \$("#username").val();
            var password_ = \$("#password").val();
            \$.post("/cgi-bin/sessionManagement.pl",
              {
                method      : "step2",
                lg_username : username_,
                lg_password : password_
              },
            function(mydata, status){
              alert(mydata);
            });
        }        
      </script>
    </head>
    <body>
      username : <input type='text' id='username'></input><br/>
      password : <input type='text' id='password'></input><br/>
      <button id='myBtn' onClick='step1Click()'>step1</button>
      <button id='myBtn' onClick='step2Click()'>step2</button>
    </body>
  </html>
EOF

}

sub login{

  my $cgi     = shift;
  my $session = shift;
  my $trials = $session->param("~login-trials") || 0;

  if($cgi->param("lg_username") eq "sarah"){ ## unthenticate
    $session->param("~logged-in",1);
    $session->param("~profile",{username=>"sarah", email=>"a\@ee.com"});
    $session->param("~login-trials", ++$trials);
    $session->clear(["~login-trials"]);
  }else{
    $session->param("~logged-in",0);
    $session->param("~login-trials", ++$trials);
  }

  open(TEST,">>/tmp/mySession");
  print TEST $session->param("~login-trials")."\n";
  close(TEST);

  my $cookie = $cgi->cookie(CGISESSID => $session->id) || $cgi->param('CGISESSID') || undef;
  print $cgi->header(-type=>'text/html',-charset=>'utf-8',-cookie=>$cookie);
  if ( $session->param("~logged-in") ) {
    my $profile = $session->param("~profile");  
    print "Hello $profile->{username}, I know it's you.your email is: $profile->{email}\n";
  }else{
    if($session->param("~login-trials")>3){
      print "your account has been locked\n";  
    }else{
      print "wrong username/password\n";
    }
  }

}

main();

sub main{

  my $cgi=new CGI;
  my $session = new CGI::Session(undef, $cgi, {Directory=>'/tmp/'});
  $session->expire('+1m');
  
  my $method = $cgi->param("method");
  if (defined($method)) {
    if($method eq "login"){
      login($cgi,$session);
    }elsif($method eq "step2"){
      step2($cgi);
    }else{
      print $cgi->header(-type=>"text/xml", -charset=>'utf-8');
      print "<info><code>1</code><msg>method does not exist</msg></info>";
    }    
    
  }else{    
    signInOut($cgi);
  }

}