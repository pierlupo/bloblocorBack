package com.example.authentification.controller;


import com.example.authentification.dto.*;
import com.example.authentification.entity.Utilisateur;
import com.example.authentification.security.JWTGenerator;
import com.example.authentification.service.UtilisateurService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;


@RequestMapping("/api/auth")
@RestController
@CrossOrigin(origins = "*", methods = {RequestMethod.GET, RequestMethod.POST})
public class UtilisateurController {
    private final AuthenticationManager authenticationManager;

    private final UtilisateurService utilisateurService;
    private final PasswordEncoder passwordEncoder;
    private final JWTGenerator generator;

    public UtilisateurController(AuthenticationManager authenticationManager, UtilisateurService utilisateurService, PasswordEncoder passwordEncoder, JWTGenerator generator) {
        this.authenticationManager = authenticationManager;
        this.utilisateurService = utilisateurService;
        this.passwordEncoder = passwordEncoder;
        this.generator = generator;
    }


    @PostMapping("login")
    public ResponseEntity<LoginResponseDTO> login(@RequestBody LoginRequestDTO loginRequestDTO) {
        try {
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequestDTO.getUsername(), loginRequestDTO.getPassword()));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            Utilisateur utilisateur = utilisateurService.trouverParUsername(loginRequestDTO.getUsername());
            return ResponseEntity.ok(LoginResponseDTO.builder().token(generator.generateToken(authentication))
                    .id(utilisateur.getId())
                    .avatar(utilisateur.getAvatar())
                    .username(utilisateur.getUsername())
                    .email(utilisateur.getEmail())
                    .firstname(utilisateur.getFirstname())
                    .isAdmin(utilisateur.isAdmin())
                    .isDriver(utilisateur.isDriver())
                    .lastname(utilisateur.getLastname())
                    .phone(utilisateur.getPhone())
                    .build());
        }catch (Exception ex) {
            throw new RuntimeException();
        }
    }

//    @PostMapping("/login") // Cette méthode gère les requêtes POST sur "/api/auth/login".
//    public ResponseEntity<JwtAuthResponse> login(@RequestBody LoginRequestDTO loginDto) {
//        // Appelle la méthode "login" de l'AuthService en passant les informations de LoginDto.
//        // Cette méthode gère le processus de connexion et renvoie le token JWT.
//        String token = utilisateurService.login(loginDto);
//
//        // Crée une instance de JwtAuthResponse pour encapsuler le token JWT.
//        JwtAuthResponse jwtAuthResponse = new JwtAuthResponse();
//        jwtAuthResponse.setAccessToken(token);
//
//        // Retourne une réponse HTTP avec l'objet JwtAuthResponse contenant le token JWT et le code de statut "200 OK".
//        return new ResponseEntity<>(jwtAuthResponse, HttpStatus.OK);
//    }

    @PostMapping("register")
    public ResponseEntity<RegisterResponseDTO> register(@RequestBody RegisterRequestDTO registerRequestDTO) {
        try {
            Utilisateur userApp = utilisateurService.enregistrerUtilisateur(registerRequestDTO.getUsername(), passwordEncoder.encode(registerRequestDTO.getPassword()),registerRequestDTO.getFirstname(),registerRequestDTO.getLastname(),registerRequestDTO.getPhone(), registerRequestDTO.getEmail(), registerRequestDTO.isAdmin(), registerRequestDTO.isDriver());
            return ResponseEntity.ok(RegisterResponseDTO.builder().id(userApp.getId()).message("User created").build());
        }catch (Exception ex) {
            throw new RuntimeException();
        }
    }
}
