package com.oasys.banksecurity.security;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.oasys.banksecurity.entity.UserInfo;

public class UserInfoUserDetails  implements UserDetails{
public String username;
public String password;
public List<GrantedAuthority> authorities;

public UserInfoUserDetails(UserInfo user) {
	username=user.getUsername();
	password=user.getPassword();
	authorities=Arrays.stream(user.getRoles().split(",")).map(i-> new SimpleGrantedAuthority(i)).collect(Collectors.toList());
}
	
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		// TODO Auto-generated method stub
		return this.authorities;
	}

	@Override
	public String getPassword() {
		// TODO Auto-generated method stub
		return this.password;
	}

	@Override
	public String getUsername() {
		// TODO Auto-generated method stubpackage com.oasys.securitydb.entity;


		return this.username;
	}

	@Override
	public boolean isAccountNonExpired() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isEnabled() {
		// TODO Auto-generated method stub
		return true;
	}

}
