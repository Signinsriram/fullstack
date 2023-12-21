package com.oasys.banksecurity.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.oasys.banksecurity.entity.Bank;
import com.oasys.banksecurity.entity.UserInfo;
import com.oasys.banksecurity.repository.BankRepository;
import com.oasys.banksecurity.repository.UserInfoRepository;
import com.oasys.banksecurity.service.AuthRequest;
import com.oasys.banksecurity.service.JwtService;

@RestController
@RequestMapping("bank")
@CrossOrigin(origins = "*")
public class BankController {
@Autowired
UserInfoRepository userepo;
@Autowired
PasswordEncoder encoder;
@Autowired
BankRepository bankrepo;
@Autowired 
JwtService jwtservice;
@Autowired 
AuthenticationManager authManager;
	
	@GetMapping("getmsg")
	public String getMsg() {
		return "god is love";
	}
	@GetMapping("getuser")
	 @PreAuthorize("hasRole('ROLE_USER')")
	public String getUser() {
		return "user is defined";
	}
	@PostMapping("insertuser")
	public String insertUser(@RequestBody UserInfo user) {
		user.setPassword(encoder.encode(user.getPassword()));
		userepo.save(user);
		return "successfully signed in a user";
	}
	@PostMapping("newaccount")
	public String insertAccount(@RequestBody Bank b) {
		bankrepo.save(b);
		return "successfully account created";
	}
	@GetMapping("getbyid/{id}")
	@PreAuthorize("hasRole('ROLE_USER','ROLE_USER')")
	public Bank getByid(@PathVariable int id) {
		return bankrepo.findById(id).get();
		
	}
	@GetMapping("getall")
	@PreAuthorize("hasRole('ROLE_ADMIN')")
	public List<Bank> getAll(){
		return bankrepo.findAll();
	}
	
	@PostMapping("authenticate")
	public String JsToken(@RequestBody AuthRequest authRequest) throws Exception {
		Authentication authentication= authManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
		if(authentication.isAuthenticated()) {
	return jwtservice.generatedToken(authRequest.getUsername());
			}
		else {
			throw new UsernameNotFoundException("invalid user!");
		}
	}
}
