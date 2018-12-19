package org.dante.springsecurity.vo;

import java.io.Serializable;
import java.util.List;
import java.util.Set;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class UserVO implements Serializable {

	private static final long serialVersionUID = 6837514648372328954L;

	private String username;
	private String password;
	private String email;
	private List<String> hobby;
	private Set<String> authCodes;

	public UserVO() {
	} 
	
	public UserVO(String username) {
		this.username = username;
	}
	
	public boolean equals(Object userVO) {
		UserVO usr = (UserVO) userVO;
		return usr == null ? false : username.equalsIgnoreCase(usr.getUsername());
	}
	
	@Override
	public int hashCode() {
		return username.hashCode();
	}
}
