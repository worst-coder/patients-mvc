package ma.emsi.patientsmvc;

import ma.emsi.patientsmvc.entities.Patient;
import ma.emsi.patientsmvc.repositories.PatientRepository;
import ma.emsi.patientsmvc.sec.service.SecurityService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.util.Date;

@SpringBootApplication
public class PatientsMvcApplication {

    public static void main(String[] args) {

        SpringApplication.run(PatientsMvcApplication.class, args);
    }

    //@Bean
    CommandLineRunner commandLineRunner(PatientRepository patientRepository){
        return args -> {
            patientRepository.save(
                    new Patient(null,"Hassan",new Date(), false, 120 ));
            patientRepository.save(
                    new Patient(null,"Mohammed",new Date(), true, 321 ));
            patientRepository.save(
                    new Patient(null,"Yasmine",new Date(), true, 650 ));
            patientRepository.save(
                    new Patient(null,"Hanae",new Date(), false, 320 ));

            patientRepository.findAll().forEach(p->{
                System.out.println(p.getNom());
            });
        };
    }
    //@Bean
    CommandLineRunner saveUsers(SecurityService securityService){
        return args -> {
            securityService.saveNewUser("hicham", "User1", "User1");
            securityService.saveNewUser("nasser", "User1", "User1");
            securityService.saveNewUser("fajr", "User1", "User1");

            securityService.saveNewRole("USER", "");
            securityService.saveNewRole("ADMIN","");

            securityService.addRoleToUser("hicham", "USER");
            securityService.addRoleToUser("hicham","ADMIN");
            securityService.addRoleToUser("nasser","USER");
            securityService.addRoleToUser("fajr","USER");
        };
    }

}


