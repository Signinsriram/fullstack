package com.oasys.banksecurity.security;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.oasys.banksecurity.entity.UserInfo;
import com.oasys.banksecurity.repository.UserInfoRepository;


@Service
public class UserInfoUserDetailsService implements UserDetailsService {
@Autowired
UserInfoRepository uirepo;
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Optional<UserInfo>userinfo=uirepo.findByusername(username);
		return userinfo.map(i->new UserInfoUserDetails(i)).orElseThrow(()->new UsernameNotFoundException("User not found with username: " + username));

	}

}
