libname SAS "D:\sas\Sas project";

*******************************************************************************************
=========================Author:Rashpinder Kaur Chahal=====================================
================================SAS PROJECT================================================
=============================Date:29 April 2025============================================
The business objective is to enhance the organization's cybersecurity defense strategy 
by understanding patterns in network attacks and identifying key characteristics of 
successful intrusions vs. blocked ones. This will help in allocating security resources 
more effectively and improving automated threat detection systems..........................
******************************************************************************************;

PROC IMPORT DATAFILE="D:\sas\Sas project\cybersecurity_final.csv"
    OUT=SAS.cyber
    DBMS=CSV
    REPLACE;
    GETNAMES=YES;
    DATAROW=2;
RUN;

*Display records;
proc print data=SAS.cyber (obs=15);run;

*
Columns	Description:
timestamp	    Date and time of the event
source_ip	    IP address initiating the connection/attack
destination_ip	Target IP address
protocol	    Network protocol used (HTTP, HTTPS, ICMP, etc.)
attack_type	    Type of cyberattack (e.g., Ransomware, SQL Injection)
severity	    Severity level (Low, Medium, High)
status	        Whether the attack was Blocked or Successful
packet_size	    Size of the packets involved
duration	    Duration of the event in seconds
num_packets	    Number of packets transferred
attack_score	Calculated risk or threat score (possibly from a model or rule engine)
;

*Identify data types;
proc contents data=SAS.cyber;
run;

*Missing entries;
proc means data=SAS.cyber n nmiss;
run;

/*Identify and Count Duplicate Records */
proc sort data=SAS.cyber out=sorted_data nodupkey dupout=duplicates;
    by _all_;
run;

/* Count of Duplicate Records */
proc sql;
    select count(*) as duplicate_count
    from duplicates;
quit;

*UNIVARIATE ANALYSIS;
*NUMERICAL VARIABLES: proc means, proc univariate, histogram, box plot;
title;
*Variable: Packet Size;
*proc means;
proc means data=SAS.cyber;
var packet_size;
run;

*proc univariate with histogram and normal line;
proc univariate data=SAS.cyber;
var packet_size;
histogram/normal;
run;

/* Boxplots for Numeric Variables */
proc sgplot data=SAS.cyber;
    vbox packet_size;
run;

*Variable: duration;
proc means data=SAS.cyber;
var duration;
run;

proc univariate data=SAS.cyber;
var duration;
histogram/normal;
run;

proc sgplot data=SAS.cyber;
vbox duration;
run;


*Variable: num_packets;
proc means data=SAS.cyber;
var num_packets;
run;

proc univariate data=SAS.cyber;
var num_packets;
histogram/normal;
run;

proc sgplot data=SAS.cyber;
vbox num_packets;
run;

*Variable: attack_score;
proc means data=SAS.cyber;
var attack_score;
run;

proc univariate data=SAS.cyber;
var attack_score;
histogram/normal;
run;

proc sgplot data=SAS.cyber;
vbox attack_score;
run;

*Categorical Variables: proc freq ;
proc freq data=SAS.cyber;
table protocol/plots=freqplot missing;
run;

proc freq data=SAS.cyber;
table attack_type/plots=freqplot missing;
run;

proc freq data=SAS.cyber;
table severity/plots=freqplot missing;
run;

proc freq data=SAS.cyber;
table status/plots=freqplot missing;
run;

*Outlier detection: Tukey's method;
%macro outlier_Analysis(data,var1,var2);
	proc univariate data=&data round=0.01;
	var &var1 &var2;
	output out=boxStats
	Qrange=iqr_var1 iqr_var2
	p75=Q3_var1 Q3_var2
	p25=Q1_var1 Q1_var2
	;
	run; 

	Data fence;
	set boxstats;
	*Tukey Method:;
	LIF_var1=Q1_var1-1.5*iqr_var1;*lower inner fence;
	UIF_var1=Q3_var1 +1.5 *iqr_var1;* upper inner fence;
/**/
/*	*Extreme Tukey Method:;*/
/*	LOF_var1=Q1_var1-3*iqr_var1;*lower outer fence;*/
/*	UOF_var1=Q3_var1 +3*iqr_var1;* upper outer fence;*/

	call symputx("LIF_var1",LIF_var1);
	call symputx("UIF_var1",UIF_var1);

	LIF_var2=Q1_var2-1.5*iqr_var2;*lower inner fence;
	UIF_var2=Q3_var2 +1.5 *iqr_var2;* upper inner fence;
	call symputx("LIF_var2",LIF_var2);
	call symputx("UIF_var2",UIF_var2);
	run;
	proc print data=fence;run;
	/*%put  &LIF_var1 &UIF_var1 &LIF_var2 &UIF_var2;*/

	data detected_outliers;
	set &data;
	if &var1 < &LIF_var1 or &var1 > &UIF_var1 or &var2 < &LIF_var2 or &var2 > &UIF_var2 ;
	run;
	proc print data=detected_outliers; run;
%mend outlier_Analysis;							
OPTIONS  MPRINT;
%outlier_Analysis(SAS.cyber,duration,num_packets);

*Test of independency:;
********************************************************
/******CHI SQUARE*****/
********************************************************;
*We use Chi squre test for finding if two categorical varaibles are independent from each other or not.

The Null and Alternate Hypotheses we are interested in knowing if there is a relationship between two categorical variables or not. 
In order to do so, we would have to use the Chi-squared test. But first, let's state our null hypothesis and 
the alternative hypothesis.

The Null Hypotheses:H0:There is no statistically significant relationship between thoes two categorical variables.

The Alternate Hypotheses:Ha:There is a statistically significant relationship between  thoes two categorical variables.

After running chi squre test and making sure that all asumption of chi_square test are satisfgied
if p-value is less than 5% you can reject null hypotheses and get this conclusion that 
"There is some correlation between thoes  two variables at 0.05 significant level
or
There is a statistically significant relationship( or association) between  thoes two categorical variables at 0.05 significant level."

Asumption of chi_square test 
The Chi-square test statistic can be used if the following conditions are satisfied:
1.N, the total frequency, should be reasonably large, say greater than 50.
2. The sample observations should be independent. This implies that no individual item should be 
included twice or more. here means they are mutully exclusive (i.e. they don't have intersection) 
in the sample( here levels of each variable need top be mutially exclusive+ can't have intersection).
3. No expected frequencies should be small. Small is a relative term. Preferably each expected frequencies 
should be larger than 10 but in any case not less than 5.
; 
TITLE "BIVARIATE  ANALYSIS: Attack Type AND Severity";

PROC FREQ DATA=SAS.cyber;
TABLE  attack_type * severity /chisq;
RUN; 

TITLE "BIVARIATE  ANALYSIS: Status AND Severity";

PROC FREQ DATA=SAS.cyber;
TABLE  status * severity /chisq;
RUN;

TITLE "BIVARIATE  ANALYSIS: Status AND Attack Type";

PROC FREQ DATA=SAS.cyber;
TABLE  attack_type * status /chisq;
RUN;

TITLE "BIVARIATE  ANALYSIS: Status AND Protocol";

PROC FREQ DATA=SAS.cyber;
TABLE  protocol * status /chisq;
RUN;

*
There is no statistically significant association between the variables (p-values > 0.05.
The strength of association is very weak, as shown by low values of Phi, 
Contingency Coefficient, and Cramer's V.
;


/* Visualizing data using cluster bar chart*/

TITLE1 "CLUSTER BAR CHART ";
TITLE2 "COMPARISON BETWEEN PROTOCOL AND STATUS "; 
PROC SGPLOT DATA = SAS.cyber;
VBAR status / GROUP = protocol GROUPDISPLAY=CLUSTER FILLTYPE = GRADIENT;
RUN;

TITLE1 "CLUSTER BAR CHART ";
TITLE2 "COMPARISON BETWEEN SEVERITY AND ATTACK_TYPE "; 
PROC SGPLOT DATA = SAS.cyber;
VBAR ATTACK_TYPE / GROUP = severity GROUPDISPLAY=CLUSTER FILLTYPE = GRADIENT;
RUN;

/*  CATEGORICAL V/S CONTINUOUS  */
/*Checking relation between Attack_type and Attack_score
Attack_type and Attack_score-CONTINUOUS VS CATEGORICAL-T-TEST

Assumptions for T-test:
1.Observations must be independent 
2.Data in each group should be normally distributed
3.Variances of the two groups should be equal

TEST HYPOTHESIS
H0: The mean Attack Score is equal across Attack Type.
H1: The mean Attack Score is not equal across Attack Type.
*/

/*Checking normality in each group*/
/*We can rely on CLT because we have more than 30 oBservations.*/

proc univariate data=SAS.cyber;
var attack_score;
histogram/normal;
run;

proc glm data=SAS.cyber;
class status;
model attack_score = status; * Predict attack_score based on status;
means status / hovtest=levene(type=abs) welch; * Test for homogeneity of variance and perform Welch's test if needed;
run;

TITLE1 'GROUP BOX PLOT';
TITLE2 'COMPARISON BETWEEN Status AND Attack-Score';
PROC SGPLOT DATA = SAS.cyber;
VBOX attack_score / GROUP = status;
RUN;

TITLE "BIVARIATE ANALYSIS OF CATEGORICAL V/S CONTINUOUS";
TITLE1 "Status AND Attack Type";
PROC TTEST DATA = SAS.cyber;
CLASS status;
VAR attack_score;
RUN;

*Means are very close: 49.7942 (Blocked) vs 49.3974 (Successful).

Difference in means is about 0.3967.

p-values:

Pooled variance p-value = 0.7857

Satterthwaite variance p-value = 0.7877

Both p-values are much greater than 0.05, meaning no statistically significant difference 
between the two groups' mean attack scores.

Also, from the Equality of Variances test:

Folded F p-value = 0.5077 (> 0.05), suggesting variances are not significantly different.

Summary:
There is no statistically significant difference between the "Blocked" and "Successful" 
attack scores based on this t-test.;

/*  CONTINUOUS V/S CONTINUOUS  */
/*Assumptions of Pearson Correlation
	1.Linearity
	2.Homosidasticity
	3.Independence of observations
	4.No outliers

H0:There is no correlation between Packet_Size and Num_Packets.
H1:There is correlation between Packet_Size and Num_Packets.
*/

proc sgplot data=SAS.cyber;
    scatter x=attack_score y=duration;
    reg x=attack_score y=duration; /* Adds a trend line */
run;


title ' Correlation Matrix and Scatter Plot ';
proc corr data = SAS.cyber pearson spearman kendall 
plots(maxpoint=none) = matrix(histogram);
var packet_size num_packets;
run;
title;

*Pearson correlation coefficient = 0.0133 (p-value = 0.5561)

Spearman correlation coefficient = 0.0136 (p-value = 0.5464)

Kendall Tau correlation coefficient = 0.0106 (p-value = 0.5461)

Interpretation:
All the correlation coefficients are very close to 0, meaning almost no linear or monotonic
relationship between packet_size and num_packets.

The p-values are all > 0.05, indicating no statistically significant correlation.

Summary:
There is no meaningful or significant relationship between packet_size and num_packets 
based on Pearson, Spearman, and Kendall Tau correlations.;

*Linearity;
proc sgplot data=SAS.cyber;
scatter x=attack_score y=duration;	
run;


*Multicollinearity;
proc reg data=SAS.cyber;
model attack_score = packet_size duration num_packets / vif;
run;

*Residual Normality;
title "Linear Regression: Checking Residuals for Linearity";
proc reg data=SAS.cyber plots(only)=(residualbypredicted residualplot);
model attack_score = duration;
output out=SAS.reg_out predicted=pred residual=resid;
run;

*Most points are tightly spread around the horizontal line at 0, which is good.

However, there’s a "fan-shaped" pattern with some downward residuals (below -2000), 
especially for higher predicted values.

This suggests a slight non-linearity or heteroscedasticity — variance of residuals 
increases with the predicted value.;

proc glm data=SAS.cyber;
model attack_score= duration; * Predict attack_score and duration without status;
means duration/ hovtest=levene(type=abs) welch; * Test for homogeneity of variance 
and perform Welch's test if needed;
run;


proc reg data=SAS.cyber;
    model attack_score = duration;
run;


/*
One-way ANOVA Assumptions

1.The response of interest is continuous and normally distributed for each treatment group.
2.Treatment groups are independent of one another. 
3.There are no major outliers.
4.A check for unequal variances.

H0 : There is no significant difference in the means across the groups.
H1 : At least one group mean is significantly different from the others.

*;
/*ANOVA TEST*/
TITLE1 'ANOVA TEST';
PROC ANOVA DATA = SAS.cyber;
CLASS severity;
MODEL duration = severity;
RUN;

*Dependent Variable: duration

Main Factor: severity

Model F Value = 1.13

p-value (Pr > F) = 0.3339

Key points:
p-value = 0.3339 is much greater than 0.05.

This means fail to reject the null hypothesis.

Conclusion: There is no statistically significant difference in duration across different 
levels of severity.

R-Square = 0.001732

Very low, suggesting that the model explains only about 0.17% of the variation in duration.

Quick summary:
Severity does not have a significant effect on duration based on this ANOVA test.;




